// Admin Dashboard POM — Page Object for VERITAS admin dashboard
// Uses Playwright for browser-based testing of the /admin HTML page.

class AdminDashboardPage {
  constructor(page, canisterUrl) {
    this.page = page;
    this.canisterUrl = canisterUrl;
  }

  async navigate() {
    await this.page.goto(`${this.canisterUrl}/admin`);
    await this.page.waitForSelector('h1');
  }

  async getTitle() {
    return this.page.title();
  }

  async getStatsSection() {
    return this.page.locator('.card').first();
  }

  async getStatsText() {
    const section = await this.getStatsSection();
    return section.textContent();
  }

  async getEmergencyStatus() {
    const body = this.page.locator('body');
    const text = await body.textContent();
    if (text.includes('PAUSED')) return 'paused';
    if (text.includes('ACTIVE')) return 'active';
    return 'unknown';
  }

  async getTierRows() {
    return this.page.locator('table tr');
  }

  async getTierCount() {
    return this.page.locator('table tr').count() - 1; // Exclude header
  }

  async getSourcesSection() {
    return this.page.locator('.card').nth(2);
  }
}

module.exports = { AdminDashboardPage };
