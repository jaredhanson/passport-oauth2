module.exports = {
    env: {
      // jest: true,
      mocha: true,
      node: true,
    },
    extends: [
      'airbnb-base',
    ],
    plugins: [
      // 'jest'
    ],
    rules: {
      "comma-dangle": 0,
      "no-underscore-dangle": 0,
      "no-param-reassign": 0,
      "prefer-destructuring": 0,
      // 'jest/no-disabled-tests': [2],
      // 'jest/no-focused-tests': [2],
      // 'jest/no-identical-title': [2],
      // 'jest/prefer-to-have-length': [2],
      // 'jest/valid-expect': [2],
    }
  };