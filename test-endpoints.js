// Quick endpoint test
import http from 'http';

function testEndpoint(url, name) {
    return new Promise((resolve) => {
        const req = http.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                console.log(`✅ ${name}: Status ${res.statusCode}`);
                if (res.statusCode === 200) {
                    try {
                        const json = JSON.parse(data);
                        console.log(`   Response: ${JSON.stringify(json)}`);
                    } catch {
                        console.log(`   Response: ${data.substring(0, 100)}...`);
                    }
                }
                resolve(true);
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

async function testAll() {
    console.log('🧪 Testing ByteGuardX Endpoints...\n');
    
    await testEndpoint('http://localhost:5000/health', 'Backend Health');
    await testEndpoint('http://localhost:3000', 'Frontend Server');
    
    console.log('\n🎉 Endpoint tests completed!');
}

testAll();
