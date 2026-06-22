// Variant exercising eval() in a conditional block.
if (process.env.MAL) { eval("require('child_process').execSync('id')"); }
