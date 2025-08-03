const loginSection = document.getElementById("login-section");
const twoFASection = document.getElementById("2fa-section");
const signupSection = document.getElementById("signup-section");

const signupLink = document.getElementById("signup-link");
const twoFALoginLink = document.getElementById("2fa-login-link");
const signupLoginLink = document.getElementById("signup-login-link");

signupLink.addEventListener("click", (e) => {
    e.preventDefault();

    resetLoginRecaptcha();
    loginSection.style.display = "none";
    twoFASection.style.display = "none";
    signupSection.style.display = "block";
});

twoFALoginLink.addEventListener("click", (e) => {
    e.preventDefault();

    loginSection.style.display = "block";
    twoFASection.style.display = "none";
    signupSection.style.display = "none";
});

signupLoginLink.addEventListener("click", (e) => {
    e.preventDefault();

    resetLoginRecaptcha();
    loginSection.style.display = "block";
    twoFASection.style.display = "none";
    signupSection.style.display = "none";
});

// -----------------------------------------------------

const loginForm = document.getElementById("login-form");
const loginButton = document.getElementById("login-form-submit");
const loginErrAlter = document.getElementById("login-err-alert");

let loginRecaptchaRendered = false;

loginButton.addEventListener("click", (e) => {
    e.preventDefault();

    const email = loginForm.email.value;
    const password = loginForm.password.value;
    
    // Check if reCAPTCHA is shown and get the response
    const recaptchaContainer = document.getElementById('login-recaptcha-container');
    let recaptchaToken = null;
    
    if (recaptchaContainer.style.display !== 'none') {
        recaptchaToken = grecaptcha.getResponse(window.loginRecaptchaId);
        if (!recaptchaToken) {
            loginErrAlter.innerHTML = `<span><strong>Error: </strong>Please complete the reCAPTCHA verification</span>`;
            loginErrAlter.style.display = "block";
            return;
        }
    }

    const requestBody = { email, password };
    if (recaptchaToken) {
        requestBody.recaptchaToken = recaptchaToken;
    }

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
    }).then(response => {
        if (response.status === 428) { // PRECONDITION_REQUIRED - reCAPTCHA needed
            response.json().then(data => {
                if (data.status === 'recaptcha_required') {
                    showLoginRecaptcha();
                    loginErrAlter.innerHTML = `<span><strong>Notice: </strong>Too many failed attempts. Please complete reCAPTCHA verification.</span>`;
                    loginErrAlter.style.display = "block";
                }
            });
        } else if (response.status === 206) {
            TwoFAForm.email.value = email;
            response.json().then(data => {
                TwoFAForm.login_attempt_id.value = data.loginAttemptId;
            });

            loginForm.email.value = "";
            loginForm.password.value = "";
            resetLoginRecaptcha();

            loginSection.style.display = "none";
            twoFASection.style.display = "block";
            signupSection.style.display = "none";
            loginErrAlter.style.display = "none";
        } else if (response.status === 200) {
            loginForm.email.value = "";
            loginForm.password.value = "";
            resetLoginRecaptcha();
            loginErrAlter.style.display = "none";
            alert("You have successfully logged in.");
        } else {
            // Reset reCAPTCHA on error
            if (recaptchaToken) {
                grecaptcha.reset(window.loginRecaptchaId);
            }
            
            response.json().then(data => {
                let error_msg = data.error;
                if (error_msg !== undefined && error_msg !== null && error_msg !== "") {
                    loginErrAlter.innerHTML = `<span><strong>Error: </strong>${error_msg}</span>`;
                    loginErrAlter.style.display = "block";
                } else {
                    loginErrAlter.style.display = "none";
                }
            });
        }
    });
});

function showLoginRecaptcha() {
    const recaptchaContainer = document.getElementById('login-recaptcha-container');
    recaptchaContainer.style.display = 'flex';
    
    if (!loginRecaptchaRendered) {
        window.loginRecaptchaId = grecaptcha.render('login-recaptcha', {
            'sitekey': '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'
        });
        loginRecaptchaRendered = true;
    } else {
        grecaptcha.reset(window.loginRecaptchaId);
    }
}

function resetLoginRecaptcha() {
    const recaptchaContainer = document.getElementById('login-recaptcha-container');
    recaptchaContainer.style.display = 'none';
    
    if (loginRecaptchaRendered) {
        grecaptcha.reset(window.loginRecaptchaId);
    }
}

const signupForm = document.getElementById("signup-form");
const signupButton = document.getElementById("signup-form-submit");
const signupErrAlter = document.getElementById("signup-err-alert");

signupButton.addEventListener("click", (e) => {
    e.preventDefault();

    const email = signupForm.email.value;
    const password = signupForm.password.value;
    const requires2FA = signupForm.twoFA.checked;
    
    // Get reCAPTCHA response
    const recaptchaToken = grecaptcha.getResponse();
    
    if (!recaptchaToken) {
        signupErrAlter.innerHTML = `<span><strong>Error: </strong>Please complete the reCAPTCHA verification</span>`;
        signupErrAlter.style.display = "block";
        return;
    }

    fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, requires2FA, recaptchaToken }),
    }).then(response => {
        if (response.ok) {
            signupForm.email.value = "";
            signupForm.password.value = "";
            signupForm.twoFA.checked = false;
            grecaptcha.reset(); // Reset reCAPTCHA
            signupErrAlter.style.display = "none";
            alert("You have successfully created a user.");
            loginSection.style.display = "block";
            twoFASection.style.display = "none";
            signupSection.style.display = "none";
        } else {
            grecaptcha.reset(); // Reset reCAPTCHA on error
            response.json().then(data => {
                let error_msg = data.error;
                if (error_msg !== undefined && error_msg !== null && error_msg !== "") {
                    signupErrAlter.innerHTML = `<span><strong>Error: </strong>${error_msg}</span>`;
                    signupErrAlter.style.display = "block";
                } else {
                    signupErrAlter.style.display = "none";
                }
            });
        }
    });
});

const TwoFAForm = document.getElementById("2fa-form");
const TwoFAButton = document.getElementById("2fa-form-submit");
const TwoFAErrAlter = document.getElementById("2fa-err-alert");

TwoFAButton.addEventListener("click", (e) => {
    e.preventDefault();

    const email = TwoFAForm.email.value;
    const loginAttemptId = TwoFAForm.login_attempt_id.value;
    const TwoFACode = TwoFAForm.email_code.value;

    fetch('/verify-2fa', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, loginAttemptId, "2FACode": TwoFACode }),
    }).then(response => {
        if (response.ok) {
            TwoFAForm.email.value = "";
            TwoFAForm.email_code.value = "";
            TwoFAForm.login_attempt_id.value = "";
            TwoFAErrAlter.style.display = "none";
            alert("You have successfully logged in.");
            loginSection.style.display = "block";
            twoFASection.style.display = "none";
            signupSection.style.display = "none";
        } else {
            response.json().then(data => {
                let error_msg = data.error;
                if (error_msg !== undefined && error_msg !== null && error_msg !== "") {
                    TwoFAErrAlter.innerHTML = `<span><strong>Error: </strong>${error_msg}</span>`;
                    TwoFAErrAlter.style.display = "block";
                } else {
                    TwoFAErrAlter.style.display = "none";
                }
            });
        }
    });
});