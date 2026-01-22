const puppeteer = require('puppeteer');

async function captureScreenshot(url, outputPath, username, password) {
    const browser = await puppeteer.launch({
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--ignore-certificate-errors'
        ]
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });

    // Go to Cockpit login page
    console.log('Loading Cockpit login page...');
    await page.goto('https://127.0.0.1:9090/', {
        waitUntil: 'networkidle2',
        timeout: 30000
    });

    // Wait for login form
    console.log('Waiting for login form...');
    await page.waitForSelector('#login-user-input', { timeout: 10000 });

    // Set localStorage for superuser access BEFORE logging in
    console.log('Setting superuser localStorage...');
    await page.evaluate((user) => {
        // Set superuser preference to "any" (request admin privileges)
        const superuserKey = 'superuser:' + user;
        localStorage.setItem('superuser-key', superuserKey);
        localStorage.setItem(superuserKey, 'any');
    }, username);

    // Fill login credentials
    console.log('Filling credentials...');
    await page.type('#login-user-input', username);
    await page.type('#login-password-input', password);

    // Click login button
    console.log('Clicking login...');
    await page.click('#login-button');

    // Wait for login to complete
    console.log('Waiting for login to complete...');
    try {
        await page.waitForSelector('#login-user-input', { hidden: true, timeout: 15000 });
    } catch (e) {
        const errorMsg = await page.$eval('#login-error-message', el => el.textContent).catch(() => null);
        if (errorMsg) {
            throw new Error(`Login failed: ${errorMsg}`);
        }
        await page.screenshot({ path: '/tmp/debug-login.png' });
        throw new Error('Login form did not disappear');
    }

    // Wait for dashboard to load
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Navigate to target page
    console.log(`Navigating to ${url}...`);
    await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: 30000
    });

    // Wait for page to fully render
    console.log('Waiting for page to render...');
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Take screenshot
    await page.screenshot({ path: outputPath, fullPage: false });

    console.log(`Screenshot saved: ${outputPath}`);

    await browser.close();
}

// Get arguments
const args = process.argv.slice(2);
if (args.length < 4) {
    console.error('Usage: node cockpit-screenshot.js <url> <output> <username> <password>');
    process.exit(1);
}

captureScreenshot(args[0], args[1], args[2], args[3])
    .catch(err => {
        console.error('Error:', err.message);
        process.exit(1);
    });
