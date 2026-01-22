const puppeteer = require('puppeteer');

async function captureScreenshot(outputPath, username, password) {
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

    // Go to MWDB login page
    console.log('Loading MWDB login page...');
    await page.goto('https://127.0.0.1:8443/', {
        waitUntil: 'networkidle2',
        timeout: 30000
    });

    // Wait for login form - MWDB uses different selectors
    console.log('Waiting for login form...');
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Check if we need to login
    const loginForm = await page.$('input[name="login"]') || await page.$('input[type="text"]');
    if (loginForm) {
        console.log('Filling credentials...');
        // MWDB login fields
        const usernameField = await page.$('input[name="login"]') || await page.$('input[type="text"]');
        const passwordField = await page.$('input[name="password"]') || await page.$('input[type="password"]');

        if (usernameField && passwordField) {
            await usernameField.type(username);
            await passwordField.type(password);

            // Find and click submit button
            const submitBtn = await page.$('button[type="submit"]') || await page.$('input[type="submit"]');
            if (submitBtn) {
                console.log('Clicking login...');
                await submitBtn.click();
                await new Promise(resolve => setTimeout(resolve, 3000));
            }
        }
    }

    // Wait for page to load
    console.log('Waiting for page to render...');
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Take screenshot
    await page.screenshot({ path: outputPath, fullPage: false });

    console.log(`Screenshot saved: ${outputPath}`);

    await browser.close();
}

// Get arguments
const args = process.argv.slice(2);
if (args.length < 3) {
    console.error('Usage: node mwdb-screenshot.js <output> <username> <password>');
    process.exit(1);
}

captureScreenshot(args[0], args[1], args[2])
    .catch(err => {
        console.error('Error:', err.message);
        process.exit(1);
    });
