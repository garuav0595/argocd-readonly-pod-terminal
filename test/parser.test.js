// Run: npm test   (node --test, no extra dependencies)
const test = require('node:test');
const assert = require('node:assert');
process.env.KUBECONFIG = process.env.KUBECONFIG || '/dev/null';
const { roTokenize, roSplitPipeline, roBuildArgv, roApplyFilter } = require('../server.js');

const argv = (line, cwd = '/app') => roBuildArgv(roSplitPipeline(roTokenize(line))[0], cwd);
const blocked = (line) => assert.throws(() => { const [f, ...rest] = roSplitPipeline(roTokenize(line)); roBuildArgv(f, '/app'); rest.forEach(s => roApplyFilter(s, '')); });

test('allowed commands become absolute-path argv', () => {
  assert.deepStrictEqual(argv('ls -la'), ['ls', '-la', '/app']);
  assert.deepStrictEqual(argv('cat config/app.yaml'), ['cat', '/app/config/app.yaml']);
  assert.deepStrictEqual(argv('tail -n 50 logs/app.log'), ['tail', '-n', '50', '/app/logs/app.log']);
  assert.deepStrictEqual(argv('grep -rn error logs'), ['grep', '-rn', 'error', '/app/logs']);
  assert.deepStrictEqual(argv('find . -name "*.log" -maxdepth 2'), ['find', '/app', '-name', '*.log', '-maxdepth', '2']);
});

test('anything that could change the pod is rejected', () => {
  for (const l of ['rm -rf /', 'sh', 'bash -c id', 'vi app.yaml', 'cat a; rm b', 'cat a && rm b', 'echo x > f', 'cat $(id)', 'cat `id`', 'find / -delete', 'find / -exec rm {} ;', 'tail -f app.log', 'cat a | sh', 'cat a | xargs rm']) blocked(l);
});

test('pipes are applied to the text output, not in the pod', () => {
  const log = 'INFO start\nERROR db down\nINFO ok\nERROR timeout\n';
  assert.strictEqual(roApplyFilter(['grep', 'ERROR'], log), 'ERROR db down\nERROR timeout');
  assert.strictEqual(roApplyFilter(['grep', '-c', 'ERROR'], log), '2');
  assert.strictEqual(roApplyFilter(['grep', '-iv', 'error'], log), 'INFO start\nINFO ok');
  assert.strictEqual(roApplyFilter(['head', '-n', '1'], log), 'INFO start');
  assert.strictEqual(roApplyFilter(['tail', '-1'], log), 'ERROR timeout');
  assert.strictEqual(roApplyFilter(['wc', '-l'], log), '4');
});
