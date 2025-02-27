// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use clap::{CommandFactory as _, Parser, Subcommand};
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashMap, io::IsTerminal};

use crate::auth::get_access_token;

pub mod auth;
pub mod cache;
pub mod config;
mod version;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn version() -> &'static str {
    built_info::GIT_VERSION.unwrap_or(built_info::PKG_VERSION)
}

enum CertificateSignResponse {
    V2(CertificateSignResponseV2),
    V3(CertificateSignResponseV3),
}

/// Last used in Conch 0.3
#[derive(Deserialize)]
struct CertificateSignResponseV2 {
    certificate: ssh_key::Certificate,
    platforms: Resources,
    projects: ProjectsV2,
    short_name: String,
    user: String,
}

/// First used in Conch 0.4
#[derive(Deserialize)]
struct CertificateSignResponseV3 {
    certificate: ssh_key::Certificate,
    resources: Resources,
    associations: Associations,
    user: String,
}

// TODO better name
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Associations {
    Projects(Projects),
    Resources(HashMap<String, ResourceAssociation>),
}

// Waiting on https://github.com/serde-rs/serde/issues/745
impl<'de> Deserialize<'de> for CertificateSignResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First get the object as generic JSON
        let value = serde_json::Value::deserialize(deserializer)?;
        #[derive(Deserialize)]
        struct Version {
            version: u64,
        }
        // Extract the `version` member
        let version = Version::deserialize(&value)
            .map_err(serde::de::Error::custom)?
            .version;

        // Re-deserialise to the correct struct based on the version number
        match version {
            2 => CertificateSignResponseV2::deserialize(&value).map(CertificateSignResponse::V2),
            3 => CertificateSignResponseV3::deserialize(&value).map(CertificateSignResponse::V3),
            v => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Unsigned(v),
                &"2 or 3",
            )),
        }
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
struct CaOidcResponse {
    issuer: url::Url,
    client_id: oauth2::ClientId,
    #[serde(deserialize_with = "CaOidcResponse::check_version", rename = "version")]
    _version: u32,
}

impl CaOidcResponse {
    /// The version of the response that the CA should return.
    const VERSION: u32 = 1;
    fn check_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u32::deserialize(deserializer)?;
        let expected = Self::VERSION;
        if v != expected {
            return Err(serde::de::Error::custom(format!(
                "mismatched version `{v}` for OIDC details response, expected `{expected}`"
            )));
        }
        Ok(v)
    }
}

type ProjectsV2 = HashMap<String, Vec<String>>;

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Hash, Eq, Deserialize, Serialize)]
struct ResourceAssociation {
    username: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct Project {
    name: String,
    resources: HashMap<String, ResourceAssociation>,
}

type Projects = HashMap<String, Project>;

type Resources = HashMap<String, Resource>;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Resource {
    alias: String,
    #[serde(with = "http_serde::authority")]
    hostname: http::uri::Authority,
    #[serde(with = "http_serde::option::authority")]
    proxy_jump: Option<http::uri::Authority>,
}

#[derive(Deserialize, Serialize)]
struct CertificateConfigCache {
    resources: Resources,
    associations: Associations,
    user: String,
    identity: std::path::PathBuf,
}

impl CertificateConfigCache {
    fn from_response(r: &CertificateSignResponse, identity: std::path::PathBuf) -> Self {
        match r {
            CertificateSignResponse::V2(CertificateSignResponseV2 {
                certificate: _,
                platforms,
                projects,
                short_name,
                user,
            }) => CertificateConfigCache {
                resources: platforms.clone(),
                associations: Associations::Projects(
                    projects
                        .iter()
                        .map(|(project_id, resource_ids)| {
                            (
                                project_id.to_string(),
                                Project {
                                    name: "".to_string(),
                                    resources: resource_ids
                                        .iter()
                                        .map(|resource_id| {
                                            (
                                                resource_id.to_string(),
                                                ResourceAssociation {
                                                    username: format!(
                                                        "{}.{}",
                                                        &short_name, project_id
                                                    ),
                                                },
                                            )
                                        })
                                        .collect(),
                                },
                            )
                        })
                        .collect(),
                ),
                user: user.clone(),
                identity,
            },
            CertificateSignResponse::V3(r) => CertificateConfigCache {
                resources: r.resources.clone(),
                associations: r.associations.clone(),
                user: r.user.clone(),
                identity,
            },
        }
    }

    /// Get a resource from a resource ID
    fn resource(&self, resource_id: &String) -> Result<&Resource> {
        self.resources.get(resource_id).context(format!(
            "Could not find resource details for `{}`",
            resource_id
        ))
    }

    /// Create the SSH config `Host` line for a given resource association
    fn user_host_spec(
        &self,
        prefix: Option<&String>,
        resource_id: &String,
        resource: &ResourceAssociation,
    ) -> Result<String> {
        let alias = &self.resource(resource_id)?.alias;
        let alias = if let Some(prefix) = prefix {
            format!("{}.{}", prefix, alias)
        } else {
            alias.to_string()
        };
        let project_config = format!(
            "Host {alias}\n\
                        \tUser {}\n",
            &resource.username,
        );
        Ok(project_config)
    }

    /// Make a list of SSH config `Host` entries for a set of resource associations
    /// The optional prefix will be plcd in fron of the Host alias name
    fn user_host_specs_for_resource_associations(
        &self,
        prefix: Option<&String>,
        resource_associations: &HashMap<String, ResourceAssociation>,
    ) -> Result<Vec<String>> {
        resource_associations
            .iter()
            .sorted()
            .map(|(resource_id, resource)| self.user_host_spec(prefix, resource_id, resource))
            .collect::<Result<Vec<_>>>()
    }

    fn ssh_config(&self) -> Result<String> {
        let jump_configs = self
            .resources
            .iter()
            .sorted_by_key(|x| x.0)
            .map(|(_, c)| {
                if let Some(proxy_jump) = &c.proxy_jump {
                    let jump_alias = format!("jump.{}", &c.alias);
                    let jump_config = format!(
                        "Host {jump_alias}\n\
                                \tHostname {}\n\
                                \tIdentityFile \"{1}\"\n\
                                \tCertificateFile \"{1}-cert.pub\"\n\
                            \n",
                        proxy_jump,
                        self.identity.display(),
                    );
                    let host_config = format!(
                        "Host *.{0} {0} !{jump_alias}\n\
                                \tHostname {1}\n\
                                \tProxyJump %r@{jump_alias}\n\
                                \tIdentityFile \"{2}\"\n\
                                \tCertificateFile \"{2}-cert.pub\"\n\
                                \tAddKeysToAgent yes\n\
                            \n",
                        &c.alias,
                        &c.hostname,
                        self.identity.display(),
                    );
                    format!("{}{}", jump_config, host_config)
                } else {
                    format!(
                        "Host *.{0} {0}\n\
                                \tHostname {1}\n\
                                \tIdentityFile \"{2}\"\n\
                                \tCertificateFile \"{2}-cert.pub\"\n\
                                \tAddKeysToAgent yes\n\
                            \n",
                        &c.alias,
                        &c.hostname,
                        self.identity.display(),
                    )
                }
            })
            .collect::<Vec<String>>()
            .join("");

        let alias_configs = match &self.associations {
            Associations::Projects(projects) => projects
                .iter()
                .sorted_by_key(|x| x.0)
                .map(|(project_id, project)| {
                    Ok(self
                        .user_host_specs_for_resource_associations(
                            Some(project_id),
                            &project.resources,
                        )?
                        .join("\n"))
                })
                .collect::<Result<Vec<_>>>()?,
            Associations::Resources(resource_associations) => {
                self.user_host_specs_for_resource_associations(None, resource_associations)?
            }
        };
        let config = jump_configs + &alias_configs.join("\n");
        let config = "# CLIFTON MANAGED\n".to_string() + &config;
        Ok(config)
    }
}

#[derive(Parser)]
#[command(version = version(), about, long_about = None)]
/// Connect to Isambard
struct Args {
    #[arg(
        long,
        help=format!(
            "The clifton config file to use [default: {}]",
            &default_config_path().display(),
        ),
        global=true,
    )]
    config_file: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate and retrieve signed SSH certificate
    Auth {
        /// The SSH identity (private key) to use. Should be a path like ~/.ssh/id_ed25519
        #[arg(short = 'i', long)]
        identity: Option<std::path::PathBuf>,
        /// Should the browser be opened automatically
        #[arg(long)] // See https://github.com/clap-rs/clap/issues/815 for tracking issue
        open_browser: Option<bool>,
        /// Should the QR code be shown on the screen
        #[arg(long)]
        show_qr: Option<bool>,
    },
    /// Display the OpenSSH config
    SshConfig {
        /// Generate the SSH config snippet
        #[command(subcommand)]
        command: Option<SshConfigCommands>,
    },
    /// Display the SSH command line to use for each project.
    /// Note that the given command may not work for non-standard identity file locations.
    SshCommand {
        /// The short name of the project to provide the command for
        project: String,
        /// The resource to access the project on
        platform: Option<String>, // TODO rename (and document change)
    },
    /// Empty the cache
    #[command(hide = true)]
    ClearCache,
    /// Manage the config
    #[command(hide = true)]
    Config,
}

#[derive(Subcommand)]
enum SshConfigCommands {
    /// Write the config to an SSH config file which is included in the main one
    Write {
        /// The main SSH config file to write to
        #[arg(
            long,
            default_value_os_t = dirs::home_dir()
                .expect("Could not find home directory.")
                .join(".ssh")
                .join("config")
        )]
        ssh_config: std::path::PathBuf,
    },
}

fn default_config_path() -> std::path::PathBuf {
    dirs::config_local_dir()
        .unwrap_or(
            ".".parse()
                .expect("Could not parse fallback config directory."),
        )
        .join("clifton")
        .join("config.toml")
}

fn main() -> Result<()> {
    // Read the command line arguments
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(err) => {
            err.print().context("Failed to write Clap error.")?;
            std::process::exit(64); // sysexit EX_USAGE
        }
    };

    // Load settings from the config file
    let config_file_path = match &args.config_file {
        Some(f) => match f.try_exists() {
            Ok(true) => shellexpand::path::tilde(f),
            Ok(false) => anyhow::bail!(format!("Config file `{}` not found.", &f.display())),
            Err(err) => return Err(err).context("Could not determine if config file exists."),
        },
        None => default_config_path().into(),
    };

    let config: config::Config = match std::fs::read_to_string(config_file_path) {
        Ok(config_string) => toml::from_str(&config_string)?,
        Err(_) => toml::from_str("")?,
    };

    if config.check_version {
        let grace_days = 2;
        if let Err(e) = version::check_for_new_version(
            "https://github.com/isambard-sc/clifton/releases.atom".parse()?,
            grace_days,
        )
        .context("Failed to check for new version of Clifton.")
        {
            eprintln!("{:}", &e);
        }
    }

    let cert_details_file_name = "cert.json";

    match &args.command {
        Some(Commands::Auth {
            identity,
            open_browser,
            show_qr,
        }) => {
            let open_browser = open_browser.unwrap_or(config.open_browser);
            let show_qr = show_qr.unwrap_or(config.show_qr);

            // Load the user's public key
            let identity_file = shellexpand::path::tilde(
                identity
                    .as_ref()
                    .or(config.identity.as_ref())
                    .context("No identity file specified.")?,
            );
            if !identity_file.is_file() {
                anyhow::bail!(format!(
                    "Identity file {} not found.\nEither specify the identity file (see `clifton auth --help`) or create a new key.",
                    &identity_file.display(),
                ))
            }
            let identity = match ssh_key::PrivateKey::read_openssh_file(&identity_file) {
                Ok(i) => i,
                Err(e) => {
                    match e {
                        ssh_key::Error::Encoding(_) | ssh_key::Error::FormatEncoding => {
                            if identity_file.extension().is_some_and(|e| e == "pub") {
                                anyhow::bail!(anyhow::anyhow!(e).context("Could not decode the private key. Most likely this is caused by you passing your *public* key instead of your *private* key."))
                            } else {
                                anyhow::bail!(anyhow::anyhow!(e).context("Could not decode the private key. Most likely this is caused by you trying to read an RSA key stored in an old format. Try generating a new key."))
                            }
                        }
                        _ => anyhow::bail!(
                            anyhow::anyhow!(e).context("Could not read SSH identity file.")
                        ),
                    };
                }
            };

            if !identity.is_encrypted() {
                eprintln!(
                    "Warning, the SSH identity file `{}` is unencrypted.",
                    identity_file.display()
                );
            }

            let oidc_details: CaOidcResponse =
                reqwest::blocking::get(format!("{}oidc", &config.ca_url))
                    .context("Could not get CA OIDC details.")?
                    .error_for_status()
                    .context("Could not get CA OIDC details.")?
                    .json()
                    .context("Could not parse CA OIDC details as URL.")?;

            let cert_file_path = identity_file.with_file_name(
                [
                    identity_file
                        .file_name()
                        .context("Could not understand identity file name.")?,
                    std::ffi::OsStr::new("-cert.pub"),
                ]
                .join(std::ffi::OsStr::new("")),
            );
            println!(
                "Retrieving certificate for identity `{}`.",
                &identity_file.display()
            );
            let cert = {
                let token = get_access_token(
                    &oidc_details.client_id,
                    &oidc_details.issuer,
                    open_browser,
                    show_qr,
                )?;
                get_cert(&identity, &config.ca_url, token.secret())
            };
            let cert = match cert {
                Ok(cert) => cert,
                Err(e) => {
                    cache::delete_file(cert_details_file_name).unwrap_or_default();
                    anyhow::bail!(e)
                }
            };
            let certificate = match &cert {
                CertificateSignResponse::V2(r) => &r.certificate,
                CertificateSignResponse::V3(r) => &r.certificate,
            };
            std::fs::write(
                &cert_file_path,
                format!(
                    "{}\n",
                    &certificate
                        .to_openssh()
                        .context("Could not convert certificate to OpenSSH format.")?
                ),
            )
            .context("Could not write certificate file.")?;
            let green = anstyle::Style::new()
                .fg_color(Some(anstyle::AnsiColor::Green.into()))
                .bold();
            let cert_config_cache =
                CertificateConfigCache::from_response(&cert, identity_file.to_path_buf());
            match &cert_config_cache.associations {
                Associations::Projects(projects) => match projects.len() {
                    0 => {
                        anyhow::bail!("Did not authenticate with any projects.")
                    }
                    _ => {
                        let projects = projects
                            .iter()
                            .map(|(p_id, p)| {
                                match p.name.as_str() {
                                    "" => format!("- {}", &p_id),
                                    name => format!(" - {} ({})", &p_id, name),
                                }
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        println!(
                                    "{green}Successfully authenticated as {} and downloaded SSH certificate for projects{green:#}:\n{projects}\n",
                                    &cert_config_cache.user
                                );
                    }
                },
                Associations::Resources(_resources) => println!(
                                    "{green}Successfully authenticated as {} and downloaded SSH certificate.{green:#}",
                                    &cert_config_cache.user
                                ),
            }
            type Tz = chrono::offset::Utc; // TODO This is UNIX time, not UTC
            let valid_before: chrono::DateTime<Tz> = certificate.valid_before_time().into();
            let valid_for = valid_before - Tz::now();
            cache::write_file(
                cert_details_file_name,
                serde_json::to_string(&cert_config_cache)?,
            )
            .context("Could not write certificate details cache.")?;
            println!("Certificate file written to {}", &cert_file_path.display());
            println!(
                "Certificate valid for {} hours and {} minutes.",
                valid_for.num_hours(),
                valid_for.num_minutes() % 60,
            );
            let clifton_ssh_config_path = dirs::home_dir()
                .context("")?
                .join(".ssh")
                .join("config_clifton");
            if &cert_config_cache.ssh_config()?
                != &std::fs::read_to_string(&clifton_ssh_config_path).unwrap_or_default()
            {
                let bold = anstyle::Style::new().bold();
                println!(
                    "\n{bold}Config appears to have changed.\nYou may now want to run `clifton ssh-config write` to configure your SSH config aliases.{bold:#}"
                );
            }
        }
        Some(Commands::SshConfig { command }) => {
            let f: CertificateConfigCache = serde_json::from_str(
                &cache::read_file(cert_details_file_name).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?,
            )
            .context("Could not parse certificate details cache. Try rerunning `clifton auth`.")?;
            let config = &f.ssh_config()?;
            match command {
                Some(SshConfigCommands::Write { ssh_config }) => {
                    let main_ssh_config_path = shellexpand::path::tilde(ssh_config);
                    let current_main_config =
                        std::fs::read_to_string(&main_ssh_config_path).unwrap_or_default();
                    let clifton_ssh_config_path =
                        main_ssh_config_path.with_file_name("config_clifton");
                    let include_line =
                        format!("Include \"{}\"\n", clifton_ssh_config_path.display());
                    if !current_main_config.contains(&include_line) {
                        let new_config = include_line + &current_main_config;
                        std::fs::write(&main_ssh_config_path, new_config)
                            .context("Could not write Include line to main SSH config file.")?;
                        println!(
                            "Updated {} to contain Include line.",
                            &main_ssh_config_path.display()
                        );
                    }

                    let current_clifton_config =
                        std::fs::read_to_string(&clifton_ssh_config_path).unwrap_or_default();
                    if config == &current_clifton_config {
                        println!("SSH config is already up to date.");
                    } else {
                        std::fs::write(&clifton_ssh_config_path, &config)
                            .context("Could not write clifon SSH config file.")?;
                        println!(
                            "Wrote SSH config to {}.",
                            &clifton_ssh_config_path.display()
                        );
                    }
                    println!(
                        "Available host aliases: \n - {}",
                        match &f.associations {
                            Associations::Projects(projects) => projects
                                .iter()
                                .flat_map(|(project_id, project)| {
                                    project.resources.keys().map(|resource_id| {
                                        Ok(format!(
                                            "{}.{}",
                                            project_id.clone(),
                                            &f.resources
                                                .get(resource_id)
                                                .context(
                                                    format!("Could not find resource {resource_id} in config.")
                                                )?
                                                .alias
                                        ))
                                    })
                                })
                                .collect::<Result<Vec<_>>>()?
                                .join("\n - "),
                            Associations::Resources(resources) => {
                                resources
                                    .keys()
                                    .map(|resource_id| {
                                        Ok(&f
                                            .resources
                                            .get(resource_id)
                                            .context(
                                                format!("Could not find resource {resource_id} in config."),
                                            )?
                                            .alias)
                                    })
                                    .collect::<Result<Vec<_>>>()?
                                    .into_iter()
                                    .join("\n - ")
                            }
                        }
                    );
                }
                None => {
                    eprintln!("Copy this configuration into your SSH config file");
                    eprintln!("or use `clifton ssh-config write`.");
                    eprintln!();
                    println!("{config}");
                }
            }
        }
        Some(Commands::SshCommand { project, platform }) => {
            let f: CertificateConfigCache = serde_json::from_str(
                &cache::read_file(cert_details_file_name).context(
                    "Could not read certificate details cache. Have you run `clifton auth`?",
                )?,
            )
            .context("Could not parse certificate details cache. Try rerunning `clifton auth`.")?;
            if let Some(s) = match &f.associations {
                Associations::Projects(projects) => projects
                    .iter()
                    .find(|(p_name, _)| p_name == &project)
                    .map(|p| p.1.resources.clone()),
                Associations::Resources(resources) => Some(resources).cloned(),
            } {
                let (resource_id, resource_association) = match s.len() {
                    2.. => {
                        if let Some(resource) = platform {
                            s.iter().find(|(resource_id, _)| *resource_id == resource).context("No matching resource.")
                        } else {
                            Err(anyhow::anyhow!(
                                "Ambiguous project. \
                                It's available on resources {s:?}. \
                                Try specifying the resource with `clifton ssh-command {project} <PLATFORM>`"
                            ))
                        }
                    }
                    _ => s.iter().next().ok_or(anyhow::anyhow!("No resources found for requested project.")),
                }
                .context("Could not get resource.")?;
                let resource = f
                    .resources
                    .get(resource_id)
                    .context(format!("Could not find {} in platforms.", resource_id))?;
                let line = format!(
                    "ssh {}-i '{}' -o 'CertificateFile \"{}-cert.pub\"' -o 'AddKeysToAgent yes' {}.{}@{}",
                    if let Some(j) = &resource.proxy_jump {
                        format!("-J '%r@{}' ", j)
                    } else {
                        " ".to_string()
                    },
                    f.identity.display(),
                    f.identity.display(),
                    &resource_association.username,
                    &project,
                    &resource.hostname,
                );
                if std::io::stdout().is_terminal() {
                    // OpenSSH does not seem to offer the certificate to the jump host
                    // unless it's in the default search list.
                    eprintln!("Note that if using a non-standard identity file location, the given SSH command may not work.");
                }
                println!("{line}");
            } else {
                anyhow::bail!(format!(
                    "Project {project} does not match any currently authorised for. Try rerunning `clifton auth`."
                ))
            }
        }
        Some(Commands::ClearCache) => cache::delete_all()?,
        Some(Commands::Config) => {
            println!("{}", default_config_path().display());
        }
        None => Args::command().print_help()?,
    }

    // TODO Generate known_hosts line for host certificate
    // TODO Write known_hosts line

    Ok(())
}

/// Get a signed certificate from CA
fn get_cert(
    identity: &ssh_key::PrivateKey,
    api_url: &url::Url,
    token: &String,
) -> Result<CertificateSignResponse> {
    let cert_r = reqwest::blocking::Client::builder()
        .user_agent(format!(
            "Clifton/{} (os:{}) (arch:{})",
            version(),
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
        .build()
        .context("Could not build HTTP client.")?
        .get(format!("{api_url}sign"))
        .query(&[("public_key", identity.public_key().to_string())])
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .context("Could not get certificate from CA.")?;
    if cert_r.status().is_success() {
        let cert = cert_r
            .json::<CertificateSignResponse>()
            .context("Could not parse certificate response from CA. This could be caused by an outdated version of Clifton.")?;
        Ok(cert)
    } else {
        anyhow::bail!(cert_r.text().context("Could not get error message.")?);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};
    use serde_json::json;

    #[test]
    fn test_get_cert() -> Result<()> {
        let mut server = Server::new();
        let url = server.url().parse()?;

        let private_key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )?;
        let signing_key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )?;
        let certificate = {
            let mut certificate = ssh_key::certificate::Builder::new_with_random_nonce(
                &mut ssh_key::rand_core::OsRng,
                private_key.public_key(),
                0,
                100,
            )?;
            certificate.valid_principal("nobody")?;
            certificate.sign(&signing_key)?
        };

        let mock = server
            .mock("GET", "/sign")
            .match_query(Matcher::UrlEncoded(
                "public_key".into(),
                private_key.public_key().to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "text/json")
            .with_body(
                json!({
                    "platforms": {
                        "plat1": {
                            "alias": "1.example",
                            "hostname": "1.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                        "plat2": {
                            "alias": "2.example",
                            "hostname": "2.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                    },
                    "short_name": "foo",
                    "certificate": certificate,
                    "projects": {
                        "proj1": [
                            "plat1",
                            "plat2",
                        ],
                        "proj2": [
                            "plat1",
                        ]
                    },
                    "user": "nobody@example.com",
                    "version": 2,
                })
                .to_string(),
            )
            .create();

        let cert =
            get_cert(&private_key, &url, &"foo".to_string()).context("Cannot call get_cert.")?;
        mock.assert();
        let cert = CertificateConfigCache::from_response(&cert, "/foo/bar".into());
        let config = cert.ssh_config()?;
        assert!(config.contains("Host proj1.1.example\n\tUser foo.proj1"));
        assert!(config.contains("Host proj1.2.example\n\tUser foo.proj1"));
        assert!(config.contains("Host proj2.1.example\n\tUser foo.proj2"));
        assert!(!config.contains("proj2.2.example"));

        let mock = server
            .mock("GET", "/sign")
            .match_query(Matcher::UrlEncoded(
                "public_key".into(),
                private_key.public_key().to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "text/json")
            .with_body(
                json!({
                    "resources": {
                        "plat1": {
                            "alias": "1.example",
                            "hostname": "1.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                        "plat2": {
                            "alias": "2.example",
                            "hostname": "2.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                    },
                    "certificate": certificate,
                    "associations": {
                        "projects": {
                            "proj1": {
                                "name" : "Foo project",
                                "resources" : {
                                    "plat1": {
                                        "username": "foo.1",
                                    },
                                    "plat2": {
                                        "username": "foo.2",
                                    },
                                }
                            },
                            "proj2": {
                                "name" : "Bar project",
                                "resources" : {
                                    "plat1": {
                                        "username": "foo.1",
                                    },
                                }
                            },
                        },
                    },
                    "user": "nobody@example.com",
                    "version": 3,
                })
                .to_string(),
            )
            .create();

        let cert =
            get_cert(&private_key, &url, &"foo".to_string()).context("Cannot call get_cert.")?;
        mock.assert();
        let cert = CertificateConfigCache::from_response(&cert, "/foo/bar".into());
        let config = cert.ssh_config()?;
        assert!(config.contains("Host proj1.1.example\n\tUser foo.1"));
        assert!(config.contains("Host proj1.2.example\n\tUser foo.2"));
        assert!(config.contains("Host proj2.1.example\n\tUser foo.1"));
        assert!(!config.contains("proj2.2.example"));

        let mock = server
            .mock("GET", "/sign")
            .match_query(Matcher::UrlEncoded(
                "public_key".into(),
                private_key.public_key().to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "text/json")
            .with_body(
                json!({
                    "resources": {
                        "plat1": {
                            "alias": "1.example",
                            "hostname": "1.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                        "plat2": {
                            "alias": "2.example",
                            "hostname": "2.example.com",
                            "proxy_jump": "jump.example.com"
                        },
                    },
                    "certificate": certificate,
                    "associations": {
                        "resources": {
                            "plat1": {
                                "username": "foo.1",
                            },
                            "plat2": {
                                "username": "foo.2",
                            },
                        },
                    },
                    "user": "nobody@example.com",
                    "version": 3,
                })
                .to_string(),
            )
            .create();

        let cert =
            get_cert(&private_key, &url, &"foo".to_string()).context("Cannot call get_cert.")?;
        mock.assert();
        let cert = CertificateConfigCache::from_response(&cert, "/foo/bar".into());
        let config = cert.ssh_config()?;
        assert!(config.contains("Host 1.example\n\tUser foo.1"));
        assert!(config.contains("Host 2.example\n\tUser foo.2"));

        Ok(())
    }
}
