const fs = require('fs');
const path = require('path');

function walk(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    list.forEach(file => {
        file = path.join(dir, file);
        const stat = fs.statSync(file);
        if (stat && stat.isDirectory()) {
            results = results.concat(walk(file));
        } else if (file.endsWith('.ts')) {
            results.push(file);
        }
    });
    return results;
}

const root = process.cwd();
const files = walk(root);

files.forEach(file => {
    let content = fs.readFileSync(file, 'utf-8');
    const dir = path.dirname(file);

    // Function to get relative path for an alias
    const getRel = (targetDir) => {
        const fullTarget = path.join(root, targetDir);
        let rel = path.relative(dir, fullTarget).replace(/\\/g, '/');
        if (!rel.startsWith('.')) rel = './' + rel;
        if (!rel.endsWith('/')) rel = rel + '/';
        return rel;
    };

    const coreRel = getRel('core');
    const sharedRel = getRel('packages/shared');

    let newContent = content;

    // Use regex to catch '@core/' and replace with coreRel
    // Example: import ... from '@core/engine/utils'
    // become: import ... from '../../../core/engine/utils' (if at that depth)

    newContent = newContent.replace(/(['"])@core\//g, `$1${coreRel}`);
    newContent = newContent.replace(/(['"])@shared\//g, `$1${sharedRel}`);

    if (content !== newContent) {
        fs.writeFileSync(file, newContent);
        console.log(`Fixed: ${file} (core: ${coreRel}, shared: ${sharedRel})`);
    }
});
