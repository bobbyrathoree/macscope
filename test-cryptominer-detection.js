#!/usr/bin/env node

/**
 * Test script to demonstrate cryptocurrency miner behavioral detection
 *
 * This demonstrates the detection logic without actually running malware.
 */

const testCases = [
  {
    name: "HIGH THREAT: High CPU + Mining Pool Connection",
    proc: {
      pid: 1234,
      name: "suspicious-process",
      cmd: "/usr/local/bin/suspicious-process --threads 8",
      cpu: 95.5, // High CPU usage
      user: "test"
    },
    conn: {
      outbound: 1,
      listen: 0,
      sampleRemotes: new Set(["pool.supportxmr.com:3333"]) // Mining pool
    },
    expected: {
      level: "HIGH",
      reasons: ["cryptominer-behavior"]
    }
  },
  {
    name: "MED THREAT: Mining Pool Connection (Low CPU)",
    proc: {
      pid: 1235,
      name: "test-process",
      cmd: "/usr/local/bin/test-process",
      cpu: 10.0, // Low CPU
      user: "test"
    },
    conn: {
      outbound: 1,
      listen: 0,
      sampleRemotes: new Set(["nanopool.org:8888"]) // Mining pool
    },
    expected: {
      level: "MED",
      reasons: ["mining-pool-connection"]
    }
  },
  {
    name: "MED THREAT: Mining Command Arguments",
    proc: {
      pid: 1236,
      name: "xmrig",
      cmd: "/usr/local/bin/xmrig --algo randomx --pool pool.com --wallet abc123",
      cpu: 50.0,
      user: "test"
    },
    conn: {
      outbound: 0,
      listen: 0,
      sampleRemotes: new Set()
    },
    expected: {
      level: "MED",
      reasons: ["mining-command-args"]
    }
  },
  {
    name: "HIGH THREAT: Mining Pool Port Detection",
    proc: {
      pid: 1237,
      name: "worker",
      cmd: "/usr/local/bin/worker",
      cpu: 92.0, // High CPU
      user: "test"
    },
    conn: {
      outbound: 1,
      listen: 0,
      sampleRemotes: new Set(["192.168.1.100:3333"]) // Mining pool port
    },
    expected: {
      level: "HIGH",
      reasons: ["cryptominer-behavior"]
    }
  },
  {
    name: "MED THREAT: High CPU + Network (Suspicious)",
    proc: {
      pid: 1238,
      name: "worker",
      cmd: "/usr/local/bin/worker",
      cpu: 95.0, // High CPU
      user: "test"
    },
    conn: {
      outbound: 10, // Significant network activity
      listen: 0,
      sampleRemotes: new Set(["api.example.com:443"])
    },
    expected: {
      level: "MED",
      reasons: ["high-cpu-with-network"]
    }
  },
  {
    name: "HIGH THREAT: Multiple Mining Indicators",
    proc: {
      pid: 1239,
      name: "xmrig",
      cmd: "/usr/local/bin/xmrig --algo cryptonight --pool stratum+tcp://pool.com --wallet xyz",
      cpu: 98.0, // High CPU
      user: "test"
    },
    conn: {
      outbound: 1,
      listen: 0,
      sampleRemotes: new Set(["mining.nicehash.com:3334"])
    },
    expected: {
      level: "HIGH",
      reasons: ["cryptominer", "cryptominer-behavior", "mining-command-args"]
    }
  }
];

console.log("=".repeat(80));
console.log("CRYPTOCURRENCY MINER BEHAVIORAL DETECTION TEST CASES");
console.log("=".repeat(80));
console.log();

testCases.forEach((testCase, index) => {
  console.log(`Test Case ${index + 1}: ${testCase.name}`);
  console.log("-".repeat(80));

  console.log("Process Info:");
  console.log(`  PID: ${testCase.proc.pid}`);
  console.log(`  Name: ${testCase.proc.name}`);
  console.log(`  Command: ${testCase.proc.cmd}`);
  console.log(`  CPU Usage: ${testCase.proc.cpu}%`);
  console.log(`  User: ${testCase.proc.user}`);

  if (testCase.conn) {
    console.log("\nNetwork Connections:");
    console.log(`  Outbound: ${testCase.conn.outbound}`);
    console.log(`  Listen: ${testCase.conn.listen}`);
    if (testCase.conn.sampleRemotes.size > 0) {
      console.log(`  Remote Addresses: ${Array.from(testCase.conn.sampleRemotes).join(", ")}`);
    }
  }

  console.log("\nExpected Detection:");
  console.log(`  Threat Level: ${testCase.expected.level}`);
  console.log(`  Reasons: ${testCase.expected.reasons.join(", ")}`);

  console.log("\nDetection Logic:");

  // Simulate detection logic
  const HIGH_CPU_THRESHOLD = 90;
  const hasSustainedHighCpu = testCase.proc.cpu > HIGH_CPU_THRESHOLD;
  const miningPoolPorts = ['3333', '3334', '4444', '5555', '8888', '14444', '14433'];
  const miningDomainKeywords = [
    'pool', 'mining', 'miner', 'hashvault', 'supportxmr',
    'nanopool', 'nicehash', 'stratum'
  ];
  const miningCmdArgs = [
    '--algo', '--pool', '--wallet', '-o stratum', '--donate-level',
    '--user', '--pass', '--cpu-priority', '--threads', '--cpu-affinity',
    '--randomx', '--cryptonight', '--ethash', '--kawpow'
  ];

  const cmdLower = testCase.proc.cmd.toLowerCase();

  let hasMiningPoolConnection = false;
  if (testCase.conn && testCase.conn.sampleRemotes.size > 0) {
    const remotesArray = Array.from(testCase.conn.sampleRemotes);
    for (const remote of remotesArray) {
      const remoteLower = remote.toLowerCase();
      const port = remote.split(':')[1];

      if (port && miningPoolPorts.includes(port)) {
        console.log(`  ✓ Mining pool port detected: ${port}`);
        hasMiningPoolConnection = true;
        break;
      }

      if (miningDomainKeywords.some(keyword => remoteLower.includes(keyword))) {
        console.log(`  ✓ Mining-related domain detected: ${remote}`);
        hasMiningPoolConnection = true;
        break;
      }
    }
  }

  const hasMiningCmdArgs = miningCmdArgs.some(arg =>
    cmdLower.includes(arg.toLowerCase())
  );

  if (hasSustainedHighCpu) {
    console.log(`  ✓ High CPU usage detected: ${testCase.proc.cpu}% (threshold: ${HIGH_CPU_THRESHOLD}%)`);
  }

  if (hasMiningCmdArgs) {
    console.log(`  ✓ Mining-related command arguments detected`);
  }

  if (hasSustainedHighCpu && hasMiningPoolConnection) {
    console.log(`  ✓ MATCH: High CPU + Mining Pool Connection → cryptominer-behavior (HIGH)`);
  } else if (hasMiningPoolConnection && testCase.conn.outbound > 0) {
    console.log(`  ✓ MATCH: Mining Pool Connection → mining-pool-connection (MED)`);
  } else if (hasMiningCmdArgs) {
    console.log(`  ✓ MATCH: Mining Command Arguments → mining-command-args (MED)`);
  } else if (hasSustainedHighCpu && testCase.conn && testCase.conn.outbound > 5) {
    console.log(`  ✓ MATCH: High CPU + Network Activity → high-cpu-with-network (MED)`);
  }

  console.log();
  console.log("=".repeat(80));
  console.log();
});

console.log("\nKEY DETECTION FEATURES:");
console.log("1. High CPU Threshold: >90% sustained CPU usage");
console.log("2. Mining Pool Ports: 3333, 3334, 4444, 5555, 8888, 14444, 14433");
console.log("3. Mining Domain Keywords: pool, mining, miner, hashvault, supportxmr, nanopool, nicehash, stratum, etc.");
console.log("4. Mining Command Arguments: --algo, --pool, --wallet, -o stratum, --randomx, --cryptonight, etc.");
console.log();
console.log("THREAT LEVEL LOGIC:");
console.log("• HIGH: High CPU (>90%) + Mining Pool Connection → 'cryptominer-behavior'");
console.log("• MED:  Mining Pool Connection (without high CPU) → 'mining-pool-connection'");
console.log("• MED:  Mining-related command arguments → 'mining-command-args'");
console.log("• MED:  High CPU + Significant network activity → 'high-cpu-with-network'");
console.log();
