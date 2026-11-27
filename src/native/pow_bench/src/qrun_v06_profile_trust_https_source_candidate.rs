//! HTTPS read adapter for signed Q6TS profile-trust envelopes.
//! Transport is untrusted: callers MUST verify signatures and the independently administered
//! monotonic floor. This module does not publish trust records or provision operator independence.
use crate::qrun_v06_profile_trust_candidate::QRunV06ProfileTrustSource;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
const MAX_ENVELOPE_BYTES: usize = 65_536;
const CURL_TIMEOUT_SECONDS: &str = "15";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06TrustHttpOutput {
    pub success: bool,
    pub body: Vec<u8>,
    pub error: String,
}
pub trait QRunV06TrustHttpRunner: Send {
    fn get(&mut self, url: &str) -> Result<QRunV06TrustHttpOutput, String>;
}
pub struct CurlQRunV06TrustHttpRunner {
    executable: PathBuf,
}
impl CurlQRunV06TrustHttpRunner {
    fn new(executable: impl AsRef<Path>) -> Result<Self, String> {
        if executable.as_ref().as_os_str().is_empty() {
            return Err("curl executable path is empty".to_owned());
        }
        Ok(Self {
            executable: executable.as_ref().to_path_buf(),
        })
    }
}
impl QRunV06TrustHttpRunner for CurlQRunV06TrustHttpRunner {
    fn get(&mut self, url: &str) -> Result<QRunV06TrustHttpOutput, String> {
        let output = Command::new(&self.executable)
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                CURL_TIMEOUT_SECONDS,
                "--max-filesize",
                "65536",
                "--proto",
                "=https",
                "--output",
                "-",
                url,
            ])
            .output()
            .map_err(|error| format!("failed to execute curl: {error}"))?;
        Ok(QRunV06TrustHttpOutput {
            success: output.status.success(),
            body: output.stdout,
            error: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}
/// Reads GET {base}/v1/q6ts/{network_hex}/{profile_hex} over HTTPS.
/// The base URL must be configured out-of-band.
pub struct HttpsQRunV06ProfileTrustSource<R = CurlQRunV06TrustHttpRunner> {
    base_url: String,
    runner: R,
}
impl HttpsQRunV06ProfileTrustSource<CurlQRunV06TrustHttpRunner> {
    pub fn new(
        base_url: impl Into<String>,
        curl_executable: impl AsRef<Path>,
    ) -> Result<Self, String> {
        Self::with_runner(base_url, CurlQRunV06TrustHttpRunner::new(curl_executable)?)
    }
}
impl<R: QRunV06TrustHttpRunner> HttpsQRunV06ProfileTrustSource<R> {
    pub fn with_runner(base_url: impl Into<String>, runner: R) -> Result<Self, String> {
        let base_url = base_url.into();
        let authority = base_url
            .strip_prefix("https://")
            .ok_or_else(|| "Q6TS trust source URL must use HTTPS".to_owned())?;
        if authority.is_empty()
            || base_url
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            || base_url.contains('?')
            || base_url.contains('#')
            || authority.starts_with('/')
            || authority.contains('@')
            || authority.split('/').next().unwrap_or("").is_empty()
        {
            return Err("invalid Q6TS trust source base URL".to_owned());
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            runner,
        })
    }
    fn hex32(value: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in value {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
impl<R: QRunV06TrustHttpRunner> QRunV06ProfileTrustSource for HttpsQRunV06ProfileTrustSource<R> {
    type Error = String;
    fn read_current_signed_record(
        &mut self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Vec<u8>, Self::Error> {
        let url = format!(
            "{}/v1/q6ts/{}/{}",
            self.base_url,
            Self::hex32(network_id),
            Self::hex32(profile_id)
        );
        let response = self.runner.get(&url)?;
        if !response.success {
            return Err(format!("Q6TS HTTPS read failed: {}", response.error));
        }
        if response.body.is_empty() || response.body.len() > MAX_ENVELOPE_BYTES {
            return Err("Q6TS HTTPS response has invalid envelope size".to_owned());
        }
        Ok(response.body)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct FakeRunner {
        urls: Vec<String>,
        responses: VecDeque<Result<QRunV06TrustHttpOutput, String>>,
    }
    impl QRunV06TrustHttpRunner for FakeRunner {
        fn get(&mut self, url: &str) -> Result<QRunV06TrustHttpOutput, String> {
            self.urls.push(url.to_owned());
            self.responses.pop_front().expect("test response")
        }
    }
    #[test]
    fn builds_network_profile_scoped_url_and_returns_body() {
        let runner = FakeRunner {
            urls: Vec::new(),
            responses: VecDeque::from([Ok(QRunV06TrustHttpOutput {
                success: true,
                body: vec![1, 2, 3],
                error: String::new(),
            })]),
        };
        let mut source =
            HttpsQRunV06ProfileTrustSource::with_runner("https://trust.example/api/", runner)
                .unwrap();
        assert_eq!(
            source
                .read_current_signed_record(&[0x0a; 32], &[0x0b; 32])
                .unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(
            source.runner.urls[0],
            format!(
                "https://trust.example/api/v1/q6ts/{}/{}",
                "0a".repeat(32),
                "0b".repeat(32)
            )
        );
    }
    #[test]
    fn rejects_non_https_and_ambiguous_base_urls() {
        for url in [
            "http://trust.example",
            "https://",
            "https://user@trust.example",
            "https://trust.example?latest=1",
            "https://trust.example/#fragment",
            " https://trust.example",
        ] {
            assert!(
                HttpsQRunV06ProfileTrustSource::with_runner(
                    url,
                    FakeRunner {
                        urls: Vec::new(),
                        responses: VecDeque::new()
                    }
                )
                .is_err(),
                "accepted {url}"
            );
        }
    }
    #[test]
    fn fails_closed_on_http_error_and_invalid_body_sizes() {
        let failed = FakeRunner {
            urls: Vec::new(),
            responses: VecDeque::from([Ok(QRunV06TrustHttpOutput {
                success: false,
                body: vec![1],
                error: "HTTP 503".to_owned(),
            })]),
        };
        let mut source =
            HttpsQRunV06ProfileTrustSource::with_runner("https://trust.example", failed).unwrap();
        assert!(source
            .read_current_signed_record(&[1; 32], &[2; 32])
            .unwrap_err()
            .contains("503"));
        for body in [Vec::new(), vec![0u8; MAX_ENVELOPE_BYTES + 1]] {
            let runner = FakeRunner {
                urls: Vec::new(),
                responses: VecDeque::from([Ok(QRunV06TrustHttpOutput {
                    success: true,
                    body,
                    error: String::new(),
                })]),
            };
            let mut source =
                HttpsQRunV06ProfileTrustSource::with_runner("https://trust.example", runner)
                    .unwrap();
            assert!(source
                .read_current_signed_record(&[1; 32], &[2; 32])
                .is_err());
        }
    }
}
