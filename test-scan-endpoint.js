// Test the scan endpoint
import http from 'http';
import fs from 'fs';
import path from 'path';

// Create a test file
const testContent = `
// Test JavaScript file for scanning
function testFunction() {
    var password = "hardcoded_password"; // This should be detected
    eval("dangerous code"); // This should be flagged
    return password;
}

// SQL injection vulnerability
const query = "SELECT * FROM users WHERE id = " + userId;
`;

const testFilePath = 'test-file.js';
fs.writeFileSync(testFilePath, testContent);

// Create multipart form data manually
function createMultipartData(filePath, filename) {
    const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);
    const fileContent = fs.readFileSync(filePath);
    
    let data = '';
    data += `--${boundary}\r\n`;
    data += `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n`;
    data += `Content-Type: application/javascript\r\n\r\n`;
    
    const header = Buffer.from(data, 'utf8');
    const footer = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
    
    return {
        boundary,
        data: Buffer.concat([header, fileContent, footer])
    };
}

async function testScanEndpoint() {
    console.log('🧪 Testing ByteGuardX Scan Endpoint...\n');
    
    try {
        const multipart = createMultipartData(testFilePath, 'test-file.js');
        
        const options = {
            hostname: 'localhost',
            port: 5000,
            path: '/api/scan',
            method: 'POST',
            headers: {
                'Content-Type': `multipart/form-data; boundary=${multipart.boundary}`,
                'Content-Length': multipart.data.length
            }
        };
        
        const req = http.request(options, (res) => {
            let responseData = '';
            
            res.on('data', (chunk) => {
                responseData += chunk;
            });
            
            res.on('end', () => {
                console.log(`✅ Scan Response - Status: ${res.statusCode}`);
                console.log(`Headers:`, res.headers);
                console.log(`\nResponse Body:`);
                
                try {
                    const jsonResponse = JSON.parse(responseData);
                    console.log(JSON.stringify(jsonResponse, null, 2));
                    
                    if (jsonResponse.scan_id) {
                        console.log(`\n🔍 Scan ID: ${jsonResponse.scan_id}`);
                        console.log(`📊 Status: ${jsonResponse.status}`);
                        
                        if (jsonResponse.findings) {
                            console.log(`🚨 Findings: ${jsonResponse.findings.length}`);
                        }
                        
                        if (jsonResponse.summary) {
                            console.log(`📈 Summary: ${JSON.stringify(jsonResponse.summary, null, 2)}`);
                        }
                    }
                } catch (e) {
                    console.log(responseData);
                }
                
                // Cleanup
                fs.unlinkSync(testFilePath);
                console.log('\n🎉 Scan endpoint test completed!');
            });
        });
        
        req.on('error', (error) => {
            console.error('❌ Request error:', error.message);
            fs.unlinkSync(testFilePath);
        });
        
        req.write(multipart.data);
        req.end();
        
    } catch (error) {
        console.error('❌ Test error:', error.message);
        if (fs.existsSync(testFilePath)) {
            fs.unlinkSync(testFilePath);
        }
    }
}

testScanEndpoint();
