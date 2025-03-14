async function handleSignin(event) {
  try {
    const { email, password } = JSON.parse(event.body);
    console.log("Received signin request for:", email);
    const params = {
      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
      UserPoolId: USER_POOL_ID,
      ClientId: CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password
      }
    };
    const authResponse = await cognito.adminInitiateAuth(params).promise();
    console.log("Auth Response:", JSON.stringify(authResponse));
    if (!authResponse.AuthenticationResult) {
      console.error("AuthenticationResult is missing in response.");
      return formatResponse(400, { error: "Authentication failed. Try again." });
    }
    return formatResponse(200, {
      idToken: authResponse.AuthenticationResult.IdToken // ✅ Corrected key name
    });
  } catch (error) {
    console.error("Sign-in error:", error);
    if (error.code === "NotAuthorizedException") {
      return formatResponse(400, { error: "Invalid email or password." });
    }
    return formatResponse(400, { error: "Authentication failed." });
  }
}
 