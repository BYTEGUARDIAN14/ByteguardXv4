// Debug scan endpoint
import http from 'http';

// Test if scan endpoint exists
function testScanEndpoint() {
    console.log('🔍 Testing scan endpoint availability...\n');
    
    // Test GET request first (should return 405 Method Not Allowed)
    const getReq = http.get('http://localhost:5000/api/scan', (res) => {
        console.log(`GET /api/scan - Status: ${res.statusCode}`);
        console.log(`Headers:`, res.headers);
        
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
            console.log(`Response: ${data}\n`);
            
            // Now test POST with empty body
            testPostEndpoint();
        });
    });
    
    getReq.on('error', (error) => {
        console.error('❌ GET request failed:', error.message);
        console.log('Backend might not be running or endpoint not available\n');
    });
}

function testPostEndpoint() {
    console.log('Testing POST /api/scan with empty body...');
    
    const postData = '';
    
    const options = {
        hostname: 'localhost',
        port: 5000,
        path: '/api/scan',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': postData.length
        }
    };
    
    const req = http.request(options, (res) => {
        console.log(`POST /api/scan - Status: ${res.statusCode}`);
        console.log(`Headers:`, res.headers);
        
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
            console.log(`Response: ${data}\n`);
            
            // Test other endpoints
            testOtherEndpoints();
        });
    });
    
    req.on('error', (error) => {
        console.error('❌ POST request failed:', error.message);
    });
    
    req.write(postData);
    req.end();
}

function testOtherEndpoints() {
    console.log('Testing other endpoints...');
    
    const endpoints = [
        '/health',
        '/api/v1/health',
        '/api/csrf-token'
    ];
    
    endpoints.forEach(endpoint => {
        const req = http.get(`http://localhost:5000${endpoint}`, (res) => {
            console.log(`GET ${endpoint} - Status: ${res.statusCode}`);
            
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);
                    console.log(`  Response: ${JSON.stringify(json)}`);
                } catch {
                    console.log(`  Response: ${data.substring(0, 100)}...`);
                }
            });
        });
        
        req.on('error', (error) => {
            console.error(`❌ ${endpoint} failed:`, error.message);
        });
    });
}

// Test frontend proxy
function testFrontendProxy() {
    console.log('\n🌐 Testing frontend proxy...');
    
    const req = http.get('http://localhost:3000/api/v1/health', (res) => {
        console.log(`Frontend proxy - Status: ${res.statusCode}`);
        
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
            console.log(`Proxy response: ${data}`);
        });
    });
    
    req.on('error', (error) => {
        console.error('❌ Frontend proxy failed:', error.message);
    });
}

// Run tests
testScanEndpoint();
setTimeout(testFrontendProxy, 2000);
