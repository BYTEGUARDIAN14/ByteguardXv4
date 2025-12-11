// Test dashboard endpoints
import http from 'http';

async function testEndpoint(path, name) {
    return new Promise((resolve) => {
        const req = http.get(`http://localhost:5000${path}`, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                console.log(`✅ ${name}: Status ${res.statusCode}`);
                if (res.statusCode === 200) {
                    try {
                        const json = JSON.parse(data);
                        console.log(`   Keys: ${Object.keys(json).join(', ')}`);
                        if (json.scans) console.log(`   Scans: ${json.scans.length} items`);
                        if (json.stats) console.log(`   Stats: ${Object.keys(json.stats).length} properties`);
                        if (json.scheduled_scans) console.log(`   Scheduled: ${json.scheduled_scans.length} items`);
                    } catch (e) {
                        console.log(`   Response: ${data.substring(0, 100)}...`);
                    }
                } else {
                    console.log(`   Error: ${data}`);
                }
                resolve(res.statusCode === 200);
            });
        });
        
        req.on('error', (error) => {
            console.log(`❌ ${name}: ${error.message}`);
            resolve(false);
        });
        
        req.setTimeout(5000, () => {
            console.log(`⏰ ${name}: Timeout`);
            req.destroy();
            resolve(false);
        });
    });
}

async function testDashboardEndpoints() {
    console.log('🧪 Testing Dashboard Endpoints...\n');
    
    const endpoints = [
        { path: '/api/scans/recent', name: 'Recent Scans' },
        { path: '/api/user/stats', name: 'User Stats' },
        { path: '/api/scans/scheduled', name: 'Scheduled Scans' },
        { path: '/api/auth/verify', name: 'Auth Verify' },
        { path: '/health', name: 'Health Check' }
    ];
    
    let working = 0;
    
    for (const endpoint of endpoints) {
        const success = await testEndpoint(endpoint.path, endpoint.name);
        if (success) working++;
    }
    
    console.log(`\n📊 Results: ${working}/${endpoints.length} endpoints working`);
    
    if (working === endpoints.length) {
        console.log('🎉 All dashboard endpoints are working correctly!');
    } else {
        console.log('⚠️  Some endpoints may need attention');
    }
}

testDashboardEndpoints();
