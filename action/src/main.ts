import * as core from "@actions/core";
import { exchangeToken, STSError } from "./client.js";

async function run(): Promise<void> {
  const stsUrl = core.getInput("sts-url", { required: true });
  const policy = core.getInput("policy", { required: true });
  const target = core.getInput("target", { required: true });
  const tokenVariable = core.getInput("token-variable");

  const subjectToken = await core.getIDToken(stsUrl);

  const response = await exchangeToken({
    stsUrl,
    subjectToken,
    resource: target,
    scope: policy,
  });

  const token = response.access_token;

  core.setSecret(token);
  core.setOutput("token", token);

  if (tokenVariable) {
    core.exportVariable(tokenVariable, token);
  }
}

run().catch((error) => {
  if (error instanceof STSError) {
    core.error(`STS error code: ${error.errorCode}`);
  }

  core.setFailed(error instanceof Error ? error.message : String(error));
});
