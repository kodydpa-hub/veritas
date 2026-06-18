module.exports = {
  default: {
    paths: ['tests/bdd/features/**/*.feature'],
    require: [
      'tests/bdd/step_definitions/**/*.js',
      'tests/bdd/support/world.js',
    ],
    format: ['progress-bar', 'html:tests/bdd/report.html'],
    timeout: 30000,
    retry: 0,
    publishQuiet: true,
  },
};
