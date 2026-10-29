// @ts-check
const eslint = require('@eslint/js');
const { defineConfig } = require('eslint/config');
const tseslint = require('typescript-eslint');
const angular = require('angular-eslint');

module.exports = defineConfig([
  {
    files: ['**/*.ts'],
    extends: [
      eslint.configs.recommended,
      tseslint.configs.recommended,
      tseslint.configs.stylistic,
      angular.configs.tsRecommended,
    ],
    processor: angular.processInlineTemplates,
    rules: {
      // Regla dura del monorepo: la web solo puede importar @infraward/shared-types.
      // domain, secrets y connectors son exclusivos del backend (arrastrarían TypeORM, etc.).
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@infraward/*', '!@infraward/shared-types'],
              message: 'apps/web solo puede importar @infraward/shared-types.',
            },
            {
              group: ['typeorm', 'typeorm/*', '@nestjs/*', 'bullmq', 'ioredis', 'pg'],
              message: 'Dependencia de backend: no se permite en apps/web.',
            },
          ],
        },
      ],
      '@angular-eslint/directive-selector': [
        'error',
        {
          type: 'attribute',
          prefix: 'app',
          style: 'camelCase',
        },
      ],
      '@angular-eslint/component-selector': [
        'error',
        {
          type: 'element',
          prefix: 'app',
          style: 'kebab-case',
        },
      ],
    },
  },
  {
    files: ['**/*.html'],
    extends: [
      angular.configs.templateRecommended,
      angular.configs.templateAccessibility,
    ],
    rules: {},
  },
]);
