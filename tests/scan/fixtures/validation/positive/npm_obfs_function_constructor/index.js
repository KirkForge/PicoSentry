// Variant exercising the Function() constructor — same dynamic-exec class as eval.
Function("return process.mainModule.require('child_process').execSync('id')")();
