// Test script for authentication and security features
const TEST_TOKEN = 'test-token-12345';
const BASE_URL = 'http://localhost:3000/api';

async function testEndpoint(name, options) {
  console.log(`\n🧪 Testing: ${name}`);
  try {
    const response = await fetch(`${BASE_URL}/processes/99999/kill`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(options.token && { 'Authorization': `Bearer ${options.token}` })
      },
      body: JSON.stringify(options.body || { signal: 'SIGTERM' })
    });

    const data = await response.json();
    console.log(`   Status: ${response.status}`);
    console.log(`   Response:`, data);
    return { status: response.status, data };
  } catch (err) {
    console.log(`   Error: ${err.message}`);
    return { error: err.message };
  }
}

async function runTests() {
  console.log('🚀 Starting Authentication & Security Tests');
  console.log('⚠️  Make sure to set PROCSCOPE_API_TOKEN=test-token-12345 before starting server');
  console.log('⚠️  Make sure server is running on http://localhost:3000');

  // Wait a bit to ensure server is ready
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Test 1: No authentication token
  await testEndpoint('1. No Authentication Token', {
    token: null,
    body: { signal: 'SIGTERM' }
  });

  // Test 2: Invalid authentication token
  await testEndpoint('2. Invalid Authentication Token', {
    token: 'wrong-token',
    body: { signal: 'SIGTERM' }
  });

  // Test 3: Valid token but invalid PID format
  await testEndpoint('3. Valid Token + Invalid PID (testing /999999/kill endpoint)', {
    token: TEST_TOKEN,
    body: { signal: 'SIGTERM' }
  });

  // Test 4: Valid token but invalid signal
  await testEndpoint('4. Valid Token + Invalid Signal', {
    token: TEST_TOKEN,
    body: { signal: 'SIGBAD' }
  });

  // Test 5: Valid token but protected PID
  const protectedPidUrl = `${BASE_URL}/processes/1/kill`;
  console.log(`\n🧪 Testing: 5. Valid Token + Protected PID (PID 1)`);
  try {
    const response = await fetch(protectedPidUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TEST_TOKEN}`
      },
      body: JSON.stringify({ signal: 'SIGTERM' })
    });
    const data = await response.json();
    console.log(`   Status: ${response.status}`);
    console.log(`   Response:`, data);
  } catch (err) {
    console.log(`   Error: ${err.message}`);
  }

  // Test 6: Rate limiting - make 6 requests quickly
  console.log(`\n🧪 Testing: 6. Rate Limiting (6 rapid requests)`);
  for (let i = 1; i <= 6; i++) {
    const response = await fetch(`${BASE_URL}/processes/99999/kill`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TEST_TOKEN}`
      },
      body: JSON.stringify({ signal: 'SIGTERM' })
    });
    const data = await response.json();
    console.log(`   Request ${i} - Status: ${response.status} - ${data.error || 'Success'}`);

    // Small delay between requests
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  console.log('\n✅ Tests completed!');
}

runTests().catch(console.error);
