const rtcms = require("realtime-cms")

const definition = rtcms.createServiceDefinition({
  name: "emailPassword",
  eventSourcing: true
})

module.exports = definition