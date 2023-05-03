use chrono::{offset::Utc, DateTime, NaiveDate, NaiveDateTime};

use crate::CliConfig;

pub(crate) fn extract_expiry(
    expires_in: &Option<i64>,
    expires_at: &Option<String>,
    config: &CliConfig,
) -> Result<i64, String> {
    if let Some(t) = expires_in {
        return Ok(*t);
    }

    if let Some(ts) = expires_at {
        let t = match DateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S %z") {
            Ok(t) => t.naive_utc(),
            Err(_) => match NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
                Ok(t) => t,
                Err(_) => match NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M") {
                    Ok(t) => t,
                    Err(_) => match NaiveDate::parse_from_str(ts, "%Y-%m-%d") {
                        Ok(t) => match t.and_hms_opt(0, 0, 0) {
                            None => return Err(format!(
                                "Couldnt parse expires_at({}) parameter: {}.and_hms_opt(0, 0, 0) return None",
                                ts,
                                t,
                            )),
                            Some(t) => t,
                        },
                        Err(e) => {
                            return Err(format!("Couldnt parse expires_at parameter: {}", e));
                        }
                    },
                },
            },
        };

        let duration = t.signed_duration_since(Utc::now().naive_utc());
        return Ok(duration.num_seconds());
    }

    if let Some(t) = config.expires_in {
        return Ok(t);
    }

    Err("Expiration date was not provided and config has no default".to_string())
}

#[cfg(test)]
mod tests {
    use chrono::offset::Utc;
    use chrono::Duration;

    use super::*;

    #[test]
    fn extract_from_expires_in() {
        let t = extract_expiry(
            &Some(3600),
            &Some("2020-10-20".to_string()),
            &CliConfig::new(Some(1200)),
        );
        assert_eq!(t, Ok(3600));
    }

    #[test]
    fn extract_from_config() {
        let t = extract_expiry(&None, &None, &CliConfig::new(Some(1200)));
        assert_eq!(t, Ok(1200));
    }

    #[test]
    fn extract_from_expires_at_as_date() {
        let now = Utc::now();
        let tomorrow_midnight = (now + Duration::days(1)).date().and_hms(0, 0, 0);
        let duration = tomorrow_midnight.signed_duration_since(now).num_seconds();

        let t = extract_expiry(
            &None,
            &Some(tomorrow_midnight.format("%Y-%m-%d").to_string()),
            &CliConfig::new(Some(1200)),
        );

        let t = t.expect("something went wrong");
        assert!(t == duration);
    }

    #[test]
    fn extract_from_expires_at_as_datetime() {
        let now = Utc::now();
        let tomorrow_midnight = (now + Duration::days(1)).date().and_hms(0, 0, 0);
        let duration = tomorrow_midnight.signed_duration_since(now).num_seconds();

        let t = extract_expiry(
            &None,
            &Some(tomorrow_midnight.format("%Y-%m-%d %H:%M:%S").to_string()),
            &CliConfig::new(Some(1200)),
        );

        let t = t.expect("something went wrong");
        assert!(t == duration);
    }
}
