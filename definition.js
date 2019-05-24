const rtcms = require("realtime-cms")
const validators = require("../validation")

const definition = rtcms.createServiceDefinition({
  name: "emailPassword",
  eventSourcing: true,
  validators
})

module.exports = definition