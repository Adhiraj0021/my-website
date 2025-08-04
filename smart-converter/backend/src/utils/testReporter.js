const TestResult = require('../models/TestResult');
const sequelize = require('../config/database');
const os = require('os');

class DatabaseTestReporter {
  constructor(globalConfig, options) {
    this.globalConfig = globalConfig;
    this.options = options;
    this.testResults = [];
    this.startTime = Date.now();
  }

  onRunStart(results, options) {
    console.log('🚀 Test run started - Results will be stored in database');
    this.startTime = Date.now();
  }

  onTestStart(test) {
    // Test is starting
  }

  onTestResult(test, testResult, aggregatedResult) {
    const testSuite = testResult.testFilePath.split('/').pop().replace('.test.js', '').replace('.test.js', '');
    
    testResult.testResults.forEach((result) => {
      const testData = {
        testSuite: testSuite,
        testName: result.title,
        status: result.status.toUpperCase(),
        duration: result.duration,
        errorMessage: result.failureMessages ? result.failureMessages.join('\n') : null,
        errorStack: result.failureMessages ? result.failureMessages.join('\n') : null,
        testData: {
          fullName: result.fullName,
          ancestorTitles: result.ancestorTitles,
          failureMessages: result.failureMessages,
          numPassingAsserts: result.numPassingAsserts,
          location: result.location
        },
        environment: process.env.NODE_ENV || 'test',
        nodeVersion: process.version,
        osInfo: `${os.platform()} ${os.release()}`,
        timestamp: new Date()
      };

      this.testResults.push(testData);
    });
  }

  onRunComplete(contexts, results) {
    console.log('💾 Storing test results in database...');
    
    // Store all test results in database
    this.storeTestResults()
      .then(() => {
        this.printSummary(results);
      })
      .catch(error => {
        console.error('❌ Failed to store test results:', error.message);
        this.printSummary(results);
      })
      .finally(async () => {
        try {
          await sequelize.close();
        } catch (error) {
          console.error('Error closing database connection:', error);
        }
      });
  }

  async storeTestResults() {
    try {
      // Ensure database connection
      await sequelize.authenticate();
      
      // Sync the TestResult model to ensure table exists
      await TestResult.sync({ force: false });
      
      // Bulk insert all test results
      const results = await TestResult.bulkCreate(this.testResults);
      console.log(`✅ Successfully stored ${results.length} test results in database`);
    } catch (error) {
      console.error('Error storing test results:', error);
      throw error;
    }
  }

  printSummary(results) {
    const totalTests = results.numTotalTests;
    const passedTests = results.numPassedTests;
    const failedTests = results.numFailedTests;
    const skippedTests = results.numPendingTests;
    const totalTime = (Date.now() - this.startTime) / 1000;

    console.log('\n📊 Test Summary:');
    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${passedTests} ✅`);
    console.log(`Failed: ${failedTests} ❌`);
    console.log(`Skipped: ${skippedTests} ⏭️`);
    console.log(`Duration: ${totalTime.toFixed(2)}s`);
    console.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);
  }
}

module.exports = DatabaseTestReporter; 