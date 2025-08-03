use validator::validate_email;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(s: String) -> Result<Self, String> {
        if validate_email(&s) {
            Ok(Email(s))
        } else {
            Err("Invalid email format".to_string())
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
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

    #[test]
    fn test_valid_email() {
        let email = Email::parse("test@example.com".to_string());
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_ref(), "test@example.com");
    }

    #[test]
    fn test_valid_email_with_subdomain() {
        let email = Email::parse("user@mail.example.com".to_string());
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_ref(), "user@mail.example.com");
    }

    #[test]
    fn test_valid_email_with_plus() {
        let email = Email::parse("user+tag@example.com".to_string());
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_ref(), "user+tag@example.com");
    }

    #[test]
    fn test_empty_email() {
        let email = Email::parse("".to_string());
        assert!(email.is_err());
        assert_eq!(email.unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_whitespace_only_email() {
        let email = Email::parse("   ".to_string());
        assert!(email.is_err());
        assert_eq!(email.unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_missing_at_symbol() {
        let email = Email::parse("testexample.com".to_string());
        assert!(email.is_err());
        assert_eq!(email.unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_multiple_at_symbols() {
        let email = Email::parse("test@@example.com".to_string());
        assert!(email.is_err());
        assert_eq!(email.unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_empty_local_part() {
        let email = Email::parse("@example.com".to_string());
        assert!(email.is_err());
        assert_eq!(email.unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_empty_domain_part() {
        let email = Email::parse("test@".to_string());
        assert!(email.is_err());
        assert_eq!(email.unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_domain_with_empty_parts() {
        let email = Email::parse("test@example..com".to_string());
        assert!(email.is_err());
        assert_eq!(email.unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_as_ref_trait() {
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let email_str: &str = email.as_ref();
        assert_eq!(email_str, "test@example.com");
    }

    #[test]
    fn test_fake_generated_emails() {
        // Test with 10 randomly generated valid emails
        for _ in 0..10 {
            let fake_email: String = SafeEmail().fake();
            let email = Email::parse(fake_email.clone());
            assert!(email.is_ok(), "Failed to parse fake email: {}", fake_email);
            assert_eq!(email.unwrap().as_ref(), fake_email);
        }
    }

    // Property-based test: all valid emails should parse successfully and maintain their value
    #[quickcheck]
    fn prop_valid_email_roundtrip(email: ValidEmail) -> bool {
        let email_str = email.0;
        match Email::parse(email_str.clone()) {
            Ok(parsed) => parsed.as_ref() == email_str,
            Err(_) => false,
        }
    }

    // Property-based test: emails without @ should always fail
    #[quickcheck]
    fn prop_email_without_at_fails(s: String) -> bool {
        if s.contains('@') {
            return true; // Skip strings that contain @
        }
        Email::parse(s).is_err()
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
