/**
 * The live deployment panel. Reads the program and PolicyRecord accounts named in the published
 * manifest and compares them with it, so a visitor can see that the commitment they are about
 * to pin is the one actually registered on chain, by the authority the manifest names.
 */

import { parseDeployment, type Deployment } from "../../src/cli/deployment.ts";
import { decodePolicyRecord } from "../../src/mxe/onchain.ts";
import type { RpcClient } from "../../src/solana/rpc.ts";

export interface DeploymentStatus {
  readonly deployment: Deployment;
  readonly programDeployed: boolean;
  /** The PolicyRecord's lifecycle state on chain, or "missing". */
  readonly policyStatus: string;
  /** Each way the chain disagrees with the manifest. Empty when everything matches. */
  readonly problems: readonly string[];
}

export async function checkDeployment(manifest: unknown, rpc: RpcClient): Promise<DeploymentStatus> {
  const deployment = parseDeployment(manifest, "deployment");
  const [program, policy] = await Promise.all([
    rpc.getAccountInfo(deployment.programId),
    rpc.getAccountInfo(deployment.policy),
  ]);
  const programDeployed = program !== null && program.executable;
  const base = programDeployed ? [] : [`No executable program at ${deployment.programId}`];

  if (policy === null) {
    return { deployment, programDeployed, policyStatus: "missing", problems: [...base, `No account at ${deployment.policy}`] };
  }
  if (policy.owner !== deployment.programId) {
    return { deployment, programDeployed, policyStatus: "foreign", problems: [...base, `${deployment.policy} is owned by ${policy.owner}`] };
  }
  try {
    const record = decodePolicyRecord(policy.data);
    const problems = [
      ...base,
      ...(record.commitment === deployment.commitment ? [] : [`On-chain commitment ${record.commitment} differs from the manifest`]),
      ...(record.authority === deployment.authority ? [] : [`On-chain authority ${record.authority} differs from the manifest`]),
      ...(record.status === "active" ? [] : [`The policy record is ${record.status}, not active`]),
    ];
    return { deployment, programDeployed, policyStatus: record.status, problems };
  } catch (err) {
    return { deployment, programDeployed, policyStatus: "malformed", problems: [...base, (err as Error).message] };
  }
}
