const axios = require("axios");
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const session = require("express-session");

const app = express();

app.use(cors());

app.use(express.json());

app.use(session({
    secret: "salesforce_secret",
    resave: false,
    saveUninitialized: true
}));

const PORT = 5000;

/*
    PKCE Helpers
*/
function base64URLEncode(str) {
    return str
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

function sha256(buffer) {
    return crypto.createHash("sha256").update(buffer).digest();
}

/*
    Home Route
*/
app.get("/", (req, res) => {
    res.send("Salesforce Backend Running");
});

/*
    Login Route
*/
app.get("/login", (req, res) => {

    const codeVerifier = base64URLEncode(
        crypto.randomBytes(32)
    );

    const codeChallenge = base64URLEncode(
        sha256(codeVerifier)
    );

    // Save verifier in session
    req.session.codeVerifier = codeVerifier;

    const loginUrl =
        `${process.env.LOGIN_URL}/services/oauth2/authorize` +
        `?response_type=code` +
        `&client_id=${process.env.CLIENT_ID}` +
        `&redirect_uri=${process.env.REDIRECT_URI}` +
        `&code_challenge=${codeChallenge}` +
        `&code_challenge_method=S256`;

    res.redirect(loginUrl);
});

/*
    OAuth Callback Route
*/
app.get("/callback", async (req, res) => {

    const code = req.query.code;

    const codeVerifier = req.session.codeVerifier;

    try {

        const tokenResponse = await axios.post(
            `${process.env.LOGIN_URL}/services/oauth2/token`,
            null,
            {
                params: {
                    grant_type: "authorization_code",
                    client_id: process.env.CLIENT_ID,
                    client_secret: process.env.CLIENT_SECRET,
                    redirect_uri: process.env.REDIRECT_URI,
                    code: code,
                    code_verifier: codeVerifier
                }
            }
        );

        const data = tokenResponse.data;

        res.json({
            message: "Login Successful",
            access_token: data.access_token,
            instance_url: data.instance_url
        });

    } catch (error) {

        console.log(error.response?.data || error.message);

        res.status(500).json({
            error: "OAuth Failed"
        });
    }
});
app.get("/validation-rules", async (req, res) => {
  try {
    const accessToken = req.query.access_token;

    const response = await axios.get(
      "https://orgfarm-6e89951539-dev-ed.develop.my.salesforce.com/services/data/v59.0/tooling/query/?q=SELECT+Id,ValidationName,Active,EntityDefinition.QualifiedApiName+FROM+ValidationRule",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    res.json(response.data.records);
  } catch (error) {
    console.log(error.response?.data || error.message);

    res.status(500).json({
      error: "Failed to fetch validation rules",
    });
  }
});
app.post("/toggle-rule", async (req, res) => {
  try {
    const { accessToken, instanceUrl, ruleId, currentStatus } = req.body;

    // STEP 1: Get existing validation rule metadata
    const existingRule = await axios.get(
      `${instanceUrl}/services/data/v59.0/tooling/sobjects/ValidationRule/${ruleId}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    // STEP 2: Update Active status
    await axios.patch(
      `${instanceUrl}/services/data/v59.0/tooling/sobjects/ValidationRule/${ruleId}`,
      {
        Metadata: {
          active: !currentStatus,
          description: existingRule.data.Metadata.description,
          errorConditionFormula:
            existingRule.data.Metadata.errorConditionFormula,
          errorDisplayField:
            existingRule.data.Metadata.errorDisplayField,
          errorMessage: existingRule.data.Metadata.errorMessage,
        },
      },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    res.json({
      message: "Validation Rule Updated Successfully",
    });
  } catch (error) {
    console.log(error.response?.data || error.message);

    res.status(500).json({
      error: "Failed to update validation rule",
    });
  }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});