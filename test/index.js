'use strict';

const expect = require('chai').expect;


describe('Тесты', function () {

    const msg = 'test';

    it('Пустой тест', async () => {
        expect(msg).to.equal('test');
    });

});