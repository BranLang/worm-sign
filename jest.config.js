/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  verbose: true,
  collectCoverage: true,
  coverageDirectory: 'coverage',
  testPathIgnorePatterns: ['/node_modules/', '/fixtures/', '/dist/'],
  modulePathIgnorePatterns: ['<rootDir>/dist/'],
  moduleFileExtensions: ['ts', 'js', 'json', 'node'],
};
