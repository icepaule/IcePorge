#!/usr/bin/env node
// =============================================================================
// IcePorge Status Extractor
// Extracts live status data from Cockpit dashboards (mwdb-manager, cape-manager)
//
// Usage: node extract-status.js [username] [password]
// Output: JSON to stdout
// =============================================================================

const puppeteer = require('puppeteer');

const COCKPIT_URL = 'https://127.0.0.1:9090';
const USERNAME = process.argv[2] || 'screenshot';
const PASSWORD = process.argv[3] || 'screenshot123';

async function extractStatus() {
    const browser = await puppeteer.launch({
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--ignore-certificate-errors'
        ]
    });

    const status = {
        timestamp: new Date().toISOString(),
        hostname: 'capev2',
        feeder: {
            total_processed: 0,
            today_uploaded: 0,
            urlhaus: 0,
            hybrid_analysis: 0
        },
        cape: {
            total_tasks: 0,
            pending: 0,
            completed_24h: 0,
            failed: 0,
            running: 0
        },
        system: {
            disk_usage: '0%',
            cape_status: 'unknown',
            mwdb_status: 'unknown'
        }
    };

    try {
        const page = await browser.newPage();
        await page.setViewport({ width: 1920, height: 1080 });

        // Set localStorage for superuser access before login
        await page.goto(COCKPIT_URL, { waitUntil: 'networkidle2' });
        await page.evaluate((user) => {
            const superuserKey = 'superuser:' + user;
            localStorage.setItem('superuser-key', superuserKey);
            localStorage.setItem(superuserKey, 'any');
        }, USERNAME);

        // Login
        await page.goto(COCKPIT_URL + '/system', { waitUntil: 'networkidle2' });
        await page.waitForSelector('#login-user-input', { timeout: 10000 });
        await page.type('#login-user-input', USERNAME);
        await page.type('#login-password-input', PASSWORD);
        await page.click('#login-button');
        await page.waitForFunction(
            () => !document.querySelector('#login-user-input'),
            { timeout: 30000 }
        );
        await new Promise(r => setTimeout(r, 2000));

        // Extract MWDB Manager data
        console.error('Extracting MWDB Manager data...');
        await page.goto(COCKPIT_URL + '/mwdb-manager', { waitUntil: 'networkidle2' });
        await new Promise(r => setTimeout(r, 5000)); // Wait for data to load

        const mwdbData = await page.evaluate(() => {
            const data = {};

            // Look for stat values by ID or class
            const totalProcessed = document.querySelector('#stat-total-processed, [data-stat="total-processed"]');
            const todayUploaded = document.querySelector('#stat-today-uploaded, [data-stat="today-uploaded"]');
            const urlhaus = document.querySelector('#stat-urlhaus, [data-stat="urlhaus"]');
            const hybridAnalysis = document.querySelector('#stat-hybrid-analysis, [data-stat="hybrid-analysis"]');

            // Try to find by text content in stat boxes
            const statBoxes = document.querySelectorAll('.stat-box, .stat-card, .stat-value, .metric-value');
            statBoxes.forEach(box => {
                const text = box.textContent.trim();
                const value = parseInt(text.replace(/[^\d]/g, ''));
                if (!isNaN(value)) {
                    const parent = box.closest('.stat-container, .stat-box, .metric');
                    if (parent) {
                        const label = parent.textContent.toLowerCase();
                        if (label.includes('total') && label.includes('processed')) data.total_processed = value;
                        if (label.includes('today') && label.includes('uploaded')) data.today_uploaded = value;
                        if (label.includes('urlhaus')) data.urlhaus = value;
                        if (label.includes('hybrid')) data.hybrid_analysis = value;
                    }
                }
            });

            // Alternative: look for specific text patterns
            const allText = document.body.innerText;
            const lines = allText.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                const nextLine = lines[i+1] ? lines[i+1].trim() : '';

                if (/^\d+$/.test(line)) {
                    const num = parseInt(line);
                    if (nextLine.toLowerCase().includes('total processed')) data.total_processed = num;
                    if (nextLine.toLowerCase().includes('today uploaded')) data.today_uploaded = num;
                    if (nextLine.toLowerCase().includes('urlhaus')) data.urlhaus = num;
                    if (nextLine.toLowerCase().includes('hybrid analysis')) data.hybrid_analysis = num;
                }
            }

            // Check MWDB service status
            const mwdbStatusEl = document.querySelector('.service-status, #mwdb-status');
            if (mwdbStatusEl) {
                data.mwdb_status = mwdbStatusEl.textContent.includes('running') ? 'running' : 'stopped';
            }

            return data;
        });

        if (mwdbData.total_processed) status.feeder.total_processed = mwdbData.total_processed;
        if (mwdbData.today_uploaded) status.feeder.today_uploaded = mwdbData.today_uploaded;
        if (mwdbData.urlhaus) status.feeder.urlhaus = mwdbData.urlhaus;
        if (mwdbData.hybrid_analysis) status.feeder.hybrid_analysis = mwdbData.hybrid_analysis;
        if (mwdbData.mwdb_status) status.system.mwdb_status = mwdbData.mwdb_status;

        // Extract CAPE Manager data
        console.error('Extracting CAPE Manager data...');
        await page.goto(COCKPIT_URL + '/cape-manager', { waitUntil: 'networkidle2' });
        await new Promise(r => setTimeout(r, 5000)); // Wait for data to load

        const capeData = await page.evaluate(() => {
            const data = {};

            // Look for specific stat elements
            const allText = document.body.innerText;
            const lines = allText.split('\n');

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                const nextLine = lines[i+1] ? lines[i+1].trim() : '';

                if (/^\d+$/.test(line)) {
                    const num = parseInt(line);
                    if (nextLine.toLowerCase().includes('total')) data.total_tasks = num;
                    if (nextLine.toLowerCase().includes('pending')) data.pending = num;
                    if (nextLine.toLowerCase().includes('completed') || nextLine.toLowerCase().includes('24h')) data.completed_24h = num;
                    if (nextLine.toLowerCase().includes('failed')) data.failed = num;
                    if (nextLine.toLowerCase().includes('running')) data.running = num;
                }
            }

            // Get disk usage
            const diskEl = document.querySelector('[data-stat="disk"], .disk-usage');
            if (diskEl) {
                const match = diskEl.textContent.match(/(\d+)%/);
                if (match) data.disk_usage = match[1] + '%';
            }

            // Alternative: look for percentage in text
            const percentMatch = allText.match(/(\d+)%\s*(?:used|disk|storage)/i);
            if (percentMatch) data.disk_usage = percentMatch[1] + '%';

            // Check CAPE status
            const capeStatusEl = document.querySelector('.service-status, #cape-status');
            if (capeStatusEl) {
                data.cape_status = capeStatusEl.textContent.includes('running') ? 'running' : 'stopped';
            }

            return data;
        });

        if (capeData.total_tasks) status.cape.total_tasks = capeData.total_tasks;
        if (capeData.pending) status.cape.pending = capeData.pending;
        if (capeData.completed_24h) status.cape.completed_24h = capeData.completed_24h;
        if (capeData.failed) status.cape.failed = capeData.failed;
        if (capeData.running) status.cape.running = capeData.running;
        if (capeData.disk_usage) status.system.disk_usage = capeData.disk_usage;
        if (capeData.cape_status) status.system.cape_status = capeData.cape_status;

        await browser.close();

    } catch (error) {
        console.error('Error extracting status:', error.message);
        await browser.close();
    }

    // Output JSON
    console.log(JSON.stringify(status, null, 2));
}

extractStatus();
