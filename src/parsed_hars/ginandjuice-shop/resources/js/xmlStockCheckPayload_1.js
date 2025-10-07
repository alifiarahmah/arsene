window.contentType = 'application/xml';

function payload(data) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>';
    xml += '<stockCheck>';

    for(var pair of data.entries()) {
        var key = pair[0];
        var value = pair[1];

        xml += '<' + key + '>' + value + '</' + key + '>';
    }

    xml += '</stockCheck>';
    return xml;
}