const rtcms = require("../../RTCms")

const definition = rtcms.createServiceDefinition({
  name: "emailPassword",
  eventSourcing: true
})

module.exports = definition