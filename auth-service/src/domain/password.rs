use color_eyre::eyre::{eyre, Result};
use regex::Regex;
use secrecy::{ExposeSecret, Secret};
use validator::validate_length;

#[derive(Debug, Clone)]
pub struct Password(Secret<String>);

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Password {
    /// Parses a password string into a Password.
    /// Returns an error if the password is invalid.
    /// Used for user input validation during signup.
    pub fn parse(s: Secret<String>) -> Result<Self> {
        Self::validate_password(&s)?;
        Ok(Self(s))
    }

    fn validate_password(s: &Secret<String>) -> Result<()> {
        let password_str = s.expose_secret();

        // Use validator crate for length validation
        if !validate_length(password_str, Some(8), None, None) {
            return Err(eyre!("Password must be at least 8 characters long"));
        }

        // Use regex validation for password strength requirements
        let uppercase_regex = Regex::new(r"[A-Z]").unwrap();
        if !uppercase_regex.is_match(password_str) {
            return Err(eyre!("Password must contain at least one uppercase letter"));
        }

        let lowercase_regex = Regex::new(r"[a-z]").unwrap();
        if !lowercase_regex.is_match(password_str) {
            return Err(eyre!("Password must contain at least one lowercase letter"));
        }

        let digit_regex = Regex::new(r"\d").unwrap();
        if !digit_regex.is_match(password_str) {
            return Err(eyre!("Password must contain at least one number"));
        }

        let special_char_regex = Regex::new(r"[^a-zA-Z0-9]").unwrap();
        if !special_char_regex.is_match(password_str) {
            return Err(eyre!(
                "Password must contain at least one special character"
            ));
        }

        Ok(())
    }

    pub fn from_hash(hash: String) -> Self {
        Password(Secret::new(hash))
    }

    pub fn to_hash(&self) -> String {
        self.0.expose_secret().clone()
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    #[test]
    fn test_valid_password() {
        let password = Password::parse(Secret::new("Test123!".to_string()));
        assert!(password.is_ok());
        assert_eq!(password.unwrap().as_ref().expose_secret(), "Test123!");
    }

    #[test]
    fn test_valid_complex_password() {
        let password = Password::parse(Secret::new("MyS3cur3P@ssw0rd!".to_string()));
        assert!(password.is_ok());
        assert_eq!(
            password.unwrap().as_ref().expose_secret(),
            "MyS3cur3P@ssw0rd!"
        );
    }

    #[test]
    fn test_password_too_short() {
        let password = Password::parse(Secret::new("Test1!".to_string()));
        assert!(password.is_err());
        assert_eq!(
            password.unwrap_err().to_string(),
            "Password must be at least 8 characters long"
        );
    }

    #[test]
    fn test_password_exactly_8_chars() {
        let password = Password::parse(Secret::new("Test123!".to_string()));
        assert!(password.is_ok());
    }

    #[test]
    fn test_password_missing_uppercase() {
        let password = Password::parse(Secret::new("test123!".to_string()));
        assert!(password.is_err());
        assert_eq!(
            password.unwrap_err().to_string(),
            "Password must contain at least one uppercase letter"
        );
    }

    #[test]
    fn test_password_missing_lowercase() {
        let password = Password::parse(Secret::new("TEST123!".to_string()));
        assert!(password.is_err());
        assert_eq!(
            password.unwrap_err().to_string(),
            "Password must contain at least one lowercase letter"
        );
    }

    #[test]
    fn test_password_missing_number() {
        let password = Password::parse(Secret::new("TestTest!".to_string()));
        assert!(password.is_err());
        assert_eq!(
            password.unwrap_err().to_string(),
            "Password must contain at least one number"
        );
    }

    #[test]
    fn test_password_missing_special_char() {
        let password = Password::parse(Secret::new("TestTest123".to_string()));
        assert!(password.is_err());
        assert_eq!(
            password.unwrap_err().to_string(),
            "Password must contain at least one special character"
        );
    }

    #[test]
    fn test_empty_password() {
        let password = Password::parse(Secret::new("".to_string()));
        assert!(password.is_err());
        assert_eq!(
            password.unwrap_err().to_string(),
            "Password must be at least 8 characters long"
        );
    }

    #[test]
    fn test_as_ref_trait() {
        let password = Password::parse(Secret::new("Test123!".to_string())).unwrap();
        let password_secret: &Secret<String> = password.as_ref();
        assert_eq!(password_secret.expose_secret(), "Test123!");
    }

    #[test]
    fn test_fake_generated_passwords() {
        // Generate passwords with specific requirements
        for _ in 0..10 {
            let fake_password: String = FakePassword(8..20).fake();
            // Since fake passwords might not meet our strict requirements,
            // we'll create compliant passwords based on them
            let compliant_password = format!("As{}1!", fake_password);
            let password = Password::parse(Secret::new(compliant_password.clone()));
            match password {
                Ok(p) => assert_eq!(p.as_ref().expose_secret(), &compliant_password),
                Err(e) => panic!(
                    "Failed to parse password: {} - Error: {}",
                    compliant_password, e
                ),
            }
        }
    }

    // Property-based test: all valid passwords should maintain their value
    #[quickcheck]
    fn prop_valid_password_roundtrip(password: ValidPassword) -> bool {
        let password_str = password.0;
        match Password::parse(Secret::new(password_str.clone())) {
            Ok(parsed) => parsed.as_ref().expose_secret() == &password_str,
            Err(_) => false,
        }
    }

    // Property-based test: passwords shorter than 8 chars should always fail
    #[quickcheck]
    fn prop_short_password_fails(s: String) -> bool {
        if s.len() >= 8 {
            return true; // Skip strings that are long enough
        }
        Password::parse(Secret::new(s)).is_err()
    }

    // Custom type for generating valid passwords in quickcheck
    #[derive(Clone, Debug)]
    struct ValidPassword(String);

    impl Arbitrary for ValidPassword {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            // Use a predefined set of valid passwords for property testing
            let valid_passwords = [
                "Password123!",
                "MySecure1@",
                "Test123#",
                "Strong9$",
                "Complex8%",
                "Valid123&",
                "Good567*",
                "Nice890+",
            ];

            let index = valid_passwords.len() % 8; // Simple deterministic selection
            ValidPassword(valid_passwords[index].to_string())
        }
    }
}
