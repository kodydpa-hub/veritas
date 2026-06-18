// Badge POM Component — reusable badge element
class Badge {
  constructor(page, selector) {
    this.page = page;
    this.element = page.locator(selector);
  }

  async getText() {
    return this.element.textContent();
  }

  async getColor() {
    const className = await this.element.getAttribute('class');
    if (className.includes('badge-green')) return 'green';
    if (className.includes('badge-red')) return 'red';
    if (className.includes('badge-yellow')) return 'yellow';
    return 'unknown';
  }
}

// Card POM Component — reusable card section
class Card {
  constructor(page, index = 0) {
    this.page = page;
    this.element = page.locator('.card').nth(index);
  }

  async getTitle() {
    const h2 = this.element.locator('h2');
    return h2.textContent();
  }

  async getContent() {
    return this.element.textContent();
  }
}

// Table POM Component — reusable data table
class DataTable {
  constructor(page, tableSelector = 'table') {
    this.page = page;
    this.element = page.locator(tableSelector);
  }

  async getHeaders() {
    return this.element.locator('th').allTextContents();
  }

  async getRowCount() {
    return this.element.locator('tr').count() - 1; // Exclude header
  }

  async getRow(index) {
    const cells = this.element.locator('tr').nth(index + 1).locator('td');
    return cells.allTextContents();
  }
}

module.exports = { Badge, Card, DataTable };
