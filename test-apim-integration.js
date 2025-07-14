// test-apim-integration.js - Test VulnShop APIM Integration

const https = require('https');

const APIM_URL = 'https://apim-vulnshop-t7up5q.azure-api.net/vulnshop';
const DIRECT_URL = 'http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com';

console.log('🔍 Testing VulnShop APIM Integration\n');

// Test 1: APIM Access
console.log('1. Testing APIM Access...');
https.get(`${APIM_URL}/api/products`, (res) => {
  console.log(`   Status: ${res.statusCode}`);
  console.log('   Headers with Azure/APIM:');
  Object.keys(res.headers).forEach(header => {
    if (header.toLowerCase().includes('azure') || 
        header.toLowerCase().includes('apim') || 
        header.toLowerCase().includes('x-')) {
      console.log(`     ${header}: ${res.headers[header]}`);
    }
  });
  
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    try {
      const products = JSON.parse(data);
      console.log(`   ✅ Success! Found ${products.length} products\n`);
    } catch (e) {
      console.log(`   ❌ Error parsing response: ${e.message}\n`);
    }
  });
}).on('error', (e) => {
  console.error(`   ❌ Error: ${e.message}\n`);
});

// Test 2: Attack Detection
setTimeout(() => {
  console.log('2. Testing Attack Detection...');
  const attackUrl = `${APIM_URL}/api/products?q=' OR '1'='1`;
  https.get(attackUrl, (res) => {
    console.log(`   Status: ${res.statusCode}`);
    
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
      try {
        const response = JSON.parse(data);
        if (res.statusCode === 403 && response.code === 'ATTACK_BLOCKED') {
          console.log(`   ✅ Attack blocked successfully!`);
          console.log(`   Attack Type: ${response.attack_type}`);
          console.log(`   Attack Score: ${response.attack_score}\n`);
        } else {
          console.log(`   ⚠️  Attack not blocked as expected\n`);
        }
      } catch (e) {
        console.log(`   Response: ${data}\n`);
      }
    });
  }).on('error', (e) => {
    console.error(`   ❌ Error: ${e.message}\n`);
  });
}, 1000);

// Test 3: Direct Access (should fail if properly secured)
setTimeout(() => {
  console.log('3. Testing Direct Backend Access...');
  const http = require('http');
  http.get(`${DIRECT_URL}/api/products`, (res) => {
    console.log(`   Status: ${res.statusCode}`);
    if (res.statusCode === 403) {
      console.log(`   ✅ Direct access properly blocked!\n`);
    } else if (res.statusCode === 200) {
      console.log(`   ⚠️  Direct access is still OPEN - backend needs to be secured!\n`);
    }
  }).on('error', (e) => {
    console.error(`   ❌ Error: ${e.message}\n`);
  });
}, 2000);

// Summary
setTimeout(() => {
  console.log('📋 Summary:');
  console.log('- APIM URL:', APIM_URL);
  console.log('- Backend URL:', DIRECT_URL);
  console.log('\nNext steps if needed:');
  console.log('1. Ensure APIM policy is applied (cortex-enhanced-security-policy.xml)');
  console.log('2. Get APIM IPs: az apim show --name apim-vulnshop-t7up5q --resource-group rg-vulnshop-t7up5q --query "publicIpAddresses" -o tsv');
  console.log('3. Update nginx on VM to only allow APIM IPs');
}, 3000); 