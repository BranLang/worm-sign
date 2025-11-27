function generateSarif(matches, warnings, projectRoot) {
  const results = matches.map((match) => ({
    ruleId: 'WS001',
    level: 'error',
    message: {
      text: `Package '${match.name}@${match.version}' is banned (found in ${match.section}).`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: 'package.json',
            uriBaseId: '%SRCROOT%',
          },
        },
      },
    ],
  }));

  warnings.forEach((warning) => {
    results.push({
      ruleId: 'WS002',
      level: 'warning',
      message: {
        text: warning,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: 'package.json',
              uriBaseId: '%SRCROOT%',
            },
          },
        },
      ],
    });
  });

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'worm-sign',
            informationUri: 'https://github.com/branislav-lang/banned-packages-scanner',
            rules: [
              {
                id: 'WS001',
                name: 'BannedPackage',
                shortDescription: {
                  text: 'Banned package detected',
                },
                fullDescription: {
                  text: 'A package known to be compromised by the Shai Hulud malware was detected.',
                },
                properties: {
                  tags: ['security', 'malware', 'shai-hulud'],
                  precision: 'very-high',
                  severity: 'error',
                },
              },
              {
                id: 'WS002',
                name: 'SuspiciousScript',
                shortDescription: {
                  text: 'Suspicious script detected',
                },
                fullDescription: {
                  text: 'A script in package.json contains suspicious patterns (e.g., curl, wget, base64).',
                },
                properties: {
                  tags: ['security', 'heuristic'],
                  precision: 'medium',
                  severity: 'warning',
                },
              },
            ],
          },
        },
        results: results,
      },
    ],
  };
}

module.exports = { generateSarif };
