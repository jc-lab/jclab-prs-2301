const path = require('path');
const orig = require('./jest.config');

/** @type {import('ts-jest/dist/types').InitialOptionsTsJest} */
module.exports = {
  ...orig,
  testEnvironment: 'jsdom'
};
