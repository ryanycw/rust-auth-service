use std::hash::Hash;

use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};
use validator::validate_email;

#[derive(Debug, Clone)]
pub struct Email(Secret<String>);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl Email {
    pub fn parse(s: Secret<String>) -> Result<Self> {
        match validate_email(s.expose_secret()) {
            true => Ok(Self(s)),
            false => Err(eyre!(format!(
                "{} is not a valid email.",
                s.expose_secret()
            ))),
        }
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use secrecy::Secret;

    #[test]
    fn test_valid_email() {
        let email = Email::parse(Secret::new("test@example.com".to_string()));
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_ref().expose_secret(), "test@example.com");
    }

    #[test]
    fn test_valid_email_with_subdomain() {
        let email = Email::parse(Secret::new("user@mail.example.com".to_string()));
        assert!(email.is_ok());
        assert_eq!(
            email.unwrap().as_ref().expose_secret(),
            "user@mail.example.com"
        );
    }

    #[test]
    fn test_valid_email_with_plus() {
        let email = Email::parse(Secret::new("user+tag@example.com".to_string()));
        assert!(email.is_ok());
        assert_eq!(
            email.unwrap().as_ref().expose_secret(),
            "user+tag@example.com"
        );
    }

    #[test]
    fn test_empty_email() {
        let plain_email = "".to_string();
        let email = Email::parse(Secret::new(plain_email.clone()));
        assert!(email.is_err());
        assert_eq!(
            email.unwrap_err().to_string(),
            format!("{} is not a valid email.", plain_email)
        );
    }

    #[test]
    fn test_whitespace_only_email() {
        let plain_email = "   ".to_string();
        let email = Email::parse(Secret::new(plain_email.clone()));
        assert!(email.is_err());
        assert_eq!(
            email.unwrap_err().to_string(),
            format!("{} is not a valid email.", plain_email)
        );
    }

    #[test]
    fn test_missing_at_symbol() {
        let plain_email = "testexample.com".to_string();
        let email = Email::parse(Secret::new(plain_email.clone()));
        assert!(email.is_err());
        assert_eq!(
            email.unwrap_err().to_string(),
            format!("{} is not a valid email.", plain_email)
        );
    }

    #[test]
    fn test_multiple_at_symbols() {
        let plain_email = "test@@example.com".to_string();
        let email = Email::parse(Secret::new(plain_email.clone()));
        assert!(email.is_err());
        assert_eq!(
            email.unwrap_err().to_string(),
            format!("{} is not a valid email.", plain_email)
        );
    }

    #[test]
    fn test_empty_local_part() {
        let plain_email = "@example.com".to_string();
        let email = Email::parse(Secret::new(plain_email.clone()));
        assert!(email.is_err());
        assert_eq!(
            email.unwrap_err().to_string(),
            format!("{} is not a valid email.", plain_email)
        );
    }

    #[test]
    fn test_empty_domain_part() {
        let plain_email = "test@".to_string();
        let email = Email::parse(Secret::new(plain_email.clone()));
        assert!(email.is_err());
        assert_eq!(
            email.unwrap_err().to_string(),
            format!("{} is not a valid email.", plain_email)
        );
    }

    #[test]
    fn test_domain_with_empty_parts() {
        let plain_email = "test@example..com".to_string();
        let email = Email::parse(Secret::new(plain_email.clone()));
        assert!(email.is_err());
        assert_eq!(
            email.unwrap_err().to_string(),
            format!("{} is not a valid email.", plain_email)
        );
    }

    #[test]
    fn test_as_ref_trait() {
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let email_str: &str = email.as_ref().expose_secret();
        assert_eq!(email_str, "test@example.com");
    }

    #[test]
    fn test_fake_generated_emails() {
        // Test with 10 randomly generated valid emails
        for _ in 0..10 {
            let fake_email: String = SafeEmail().fake();
            let email = Email::parse(Secret::new(fake_email.clone()));
            assert!(email.is_ok(), "Failed to parse fake email: {}", fake_email);
            assert_eq!(
                email.unwrap().as_ref().expose_secret().to_string(),
                fake_email
            );
        }
    }

    // Property-based test: all valid emails should parse successfully and maintain their value
    #[quickcheck]
    fn prop_valid_email_roundtrip(email: ValidEmail) -> bool {
        let email_str = email.0;
        match Email::parse(Secret::new(email_str.clone())) {
            Ok(parsed) => parsed.as_ref().expose_secret().to_string() == email_str,
            Err(_) => false,
        }
    }

    // Property-based test: emails without @ should always fail
    #[quickcheck]
    fn prop_email_without_at_fails(s: String) -> bool {
        if s.contains('@') {
            return true; // Skip strings that contain @
        }
        Email::parse(Secret::new(s)).is_err()
    }

    // Custom type for generating valid-looking emails in quickcheck
    #[derive(Clone, Debug)]
    struct ValidEmail(String);

    impl Arbitrary for ValidEmail {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            let email: String = SafeEmail().fake();
            ValidEmail(email)
        }
    }
}
