const http = require('http');

const PORT = 8080;

const server = http.createServer((req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    console.log(`${new Date().toISOString()} - API ${req.method} ${req.url}`);
    console.log('API Headers:', JSON.stringify(req.headers, null, 2));

    // Set JSON content type for all responses
    res.setHeader('Content-Type', 'application/json');

    // Root endpoint
    if (req.url === '/' || req.url === '') {
        res.writeHead(200);
        res.end(JSON.stringify({
            message: 'API Server is running!',
            note: 'This demonstrates path stripping - original path was stripped by proxy',
            port: PORT,
            timestamp: new Date().toISOString(),
            userEmail: req.headers['x-user-email'] || 'Not provided',
            userName: req.headers['x-user-name'] || 'Not provided',
            originalPath: 'Unknown (stripped by proxy)',
            pathStripping: 'ENABLED - paths are stripped before reaching this server'
        }, null, 2));
        return;
    }

    // Test endpoint (this will be accessed as /test via api.localhost but path will be stripped)
    if (req.url === '/test') {
        res.writeHead(200);
        res.end(JSON.stringify({
            endpoint: '/test',
            message: 'API Test endpoint working!',
            note: 'If you see this, path stripping is working correctly',
            timestamp: new Date().toISOString(),
            server: 'API Server',
            port: PORT,
            userInfo: {
                email: req.headers['x-user-email'] || 'Not provided',
                name: req.headers['x-user-name'] || 'Not provided',
                groups: req.headers['x-user-groups'] || 'Not provided'
            },
            proxyHeaders: {
                forwardedFor: req.headers['x-forwarded-for'] || 'Not provided',
                forwardedHost: req.headers['x-forwarded-host'] || 'Not provided',
                forwardedProto: req.headers['x-forwarded-proto'] || 'Not provided'
            },
            pathStrippingDemo: 'Original URL was probably /something/test, now just /test'
        }, null, 2));
        return;
    }

    // Users endpoint
    if (req.url === '/users') {
        res.writeHead(200);
        res.end(JSON.stringify({
            users: [
                { id: 1, name: 'John Doe', email: 'john@example.com' },
                { id: 2, name: 'Jane Smith', email: 'jane@example.com' },
                { id: 3, name: 'Admin User', email: 'admin@example.com' }
            ],
            requestedBy: req.headers['x-user-email'] || 'Anonymous',
            timestamp: new Date().toISOString()
        }, null, 2));
        return;
    }

    // Health endpoint
    if (req.url === '/health') {
        res.writeHead(200);
        res.end(JSON.stringify({
            status: 'healthy',
            service: 'API Server',
            port: PORT,
            uptime: process.uptime(),
            timestamp: new Date().toISOString()
        }));
        return;
    }

    // Catch all - show what path was received
    res.writeHead(200);
    res.end(JSON.stringify({
        message: 'API endpoint not found, but server is working',
        receivedPath: req.url,
        method: req.method,
        availableEndpoints: [
            'GET /',
            'GET /test', 
            'GET /users',
            'GET /health'
        ],
        note: 'Path stripping means original paths from proxy are modified',
        userEmail: req.headers['x-user-email'] || 'Not provided',
        timestamp: new Date().toISOString()
    }, null, 2));
});

server.listen(PORT, () => {
    console.log(`🔌 API Server running on port ${PORT}`);
    console.log(`📡 Access via proxy: https://api.localhost`);
    console.log(`🔧 Direct access: http://localhost:${PORT}`);
    console.log(`⚡ Path stripping enabled - /api/test becomes /test`);
    console.log(`💡 Available endpoints:`);
    console.log(`   - / (root)`);
    console.log(`   - /test (test endpoint)`);
    console.log(`   - /users (user list)`);
    console.log(`   - /health (health check)`);
});

process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down API server...');
    server.close(() => {
        console.log('✅ API Server closed');
        process.exit(0);
    });
});