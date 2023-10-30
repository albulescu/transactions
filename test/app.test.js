const request = require("supertest");
const app = require("../app.js");
const test = require("node:test");
const { expect } = require('chai');

const createTestAccounts = () => {
  return Promise.all(
    [
      request(app)
        .post('/api/auth/sign-up')
        .send({email: "jhon@doe.com", password: "asdasd"})
        .then(res => {
          console.log('Account created for: Jhon Doe');
        }),

      request(app)
        .post('/api/auth/sign-up')
        .send({email: "jhon@moe.com", password: "asdasd"})
        .then(res => {
          console.log('Account created for: Jhon Moe');
        })
    ]
  )
};

test("Should receive authentication token", () => {
  return createTestAccounts().then(() => {
    return request(app)
        .post("/api/auth/sign-in")
        .send({email: "jhon@doe.com", "password": "asdasd"})
        .then((res) => {
          expect(res.statusCode).to.equal(200, 'Expected success response')
          expect(res.body).to.have.property('access_token');
      });
  });
});

test("Test password create", () => {
  expect(validPassword)
});