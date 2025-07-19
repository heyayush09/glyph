const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3001;

// Read the HTML file
const htmlPath = path.join(__dirname, 'app.html');

const server = http.createServer((req, res) => {
    // Enable CORS for all requests
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    console.log('Headers received:', JSON.stringify(req.headers, null, 2));

    // API endpoint to return headers (for testing proxy header injection)
    if (req.url === '/api/headers') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        
        const headerInfo = {
            userEmail: req.headers['x-user-email'] || null,
            userName: req.headers['x-user-name'] || null,
            userGroups: req.headers['x-user-groups'] || null,
            headers: {}
        };
        
        // Include important headers
        Object.keys(req.headers).forEach(key => {
            if (key.toLowerCase().startsWith('x-user-') || 
                key.toLowerCase().startsWith('x-forwarded-') ||
                key.toLowerCase() === 'host' ||
                key.toLowerCase() === 'user-agent') {
                headerInfo.headers[key] = req.headers[key];
            }
        });
        
        res.end(JSON.stringify(headerInfo, null, 2));
        return;
    }
    
    // Health check endpoint
    if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: 'healthy',
            port: PORT,
            timestamp: new Date().toISOString(),
            uptime: process.uptime()
        }));
        return;
    }
    
    // Test API endpoint for the API server
    if (req.url === '/test' || req.url === '/api/test') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            message: 'API endpoint working!',
            timestamp: new Date().toISOString(),
            userEmail: req.headers['x-user-email'] || 'Not provided',
            userName: req.headers['x-user-name'] || 'Not provided',
            method: req.method,
            path: req.url,
            forwardedFor: req.headers['x-forwarded-for'] || 'Not provided',
            forwardedHost: req.headers['x-forwarded-host'] || 'Not provided',
            pathStripped: req.url.startsWith('/api/') ? 'No' : 'Yes (original: /test/...)'
        }, null, 2));
        return;
    }

    // Serve the main HTML file for all other routes
    if (fs.existsSync(htmlPath)) {
        const html = fs.readFileSync(htmlPath, 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
    } else {
        // Fallback HTML if file doesn't exist
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Test App - Port ${PORT}</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        max-width: 800px; 
                        margin: 0 auto; 
                        padding: 2rem;
                        background: #f5f5f5;
                    }
                    .header-info { 
                        background: #e8f4fd; 
                        padding: 1rem; 
                        border-radius: 8px; 
                        margin: 1rem 0;
                    }
                    pre { 
                        background: #f0f0f0; 
                        padding: 1rem; 
                        border-radius: 4px; 
                        overflow: auto;
                    }
                </style>
            </head>
            <body>
                <h1>🚀 Glyph Proxy Test App (Port ${PORT})</h1>
                <div class="header-info">
                    <h3>User Information from Headers:</h3>
                    <p><strong>Email:</strong> ${req.headers['x-user-email'] || 'Not provided'}</p>
                    <p><strong>Name:</strong> ${req.headers['x-user-name'] || 'Not provided'}</p>
                    <p><strong>Groups:</strong> ${req.headers['x-user-groups'] || 'Not provided'}</p>
                </div>
                
                <div class="header-info">
                    <h3>Proxy Headers:</h3>
                    <p><strong>Forwarded For:</strong> ${req.headers['x-forwarded-for'] || 'Not provided'}</p>
                    <p><strong>Forwarded Host:</strong> ${req.headers['x-forwarded-host'] || 'Not provided'}</p>
                    <p><strong>Forwarded Proto:</strong> ${req.headers['x-forwarded-proto'] || 'Not provided'}</p>
                </div>

                <div class="header-info">
                    <h3>All Headers:</h3>
                    <pre>${JSON.stringify(req.headers, null, 2)}</pre>
                </div>

                <div class="header-info">
                    <h3>Request Info:</h3>
                    <p><strong>Method:</strong> ${req.method}</p>
                    <p><strong>URL:</strong> ${req.url}</p>
                    <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
                </div>
            </body>
            </html>
        `);
    }
});

server.listen(PORT, () => {
    console.log(`🚀 Test application running on port ${PORT}`);
    console.log(`📱 Access via proxy: https://app.localhost`);
    console.log(`🔧 Direct access: http://localhost:${PORT}`);
    console.log(`💡 API endpoints:`);
    console.log(`   - /api/headers (header inspection)`);
    console.log(`   - /health (health check)`);
    console.log(`   - /test (API test)`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down server...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});