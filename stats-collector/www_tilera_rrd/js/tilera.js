
function build_graphs(tileraName, interval)
{
          var jqxhr = $.get("rrd_to_csv.cgi" + location.search, function(data) {

              var errorCodesName = ["OFP_NO_ERROR",
                                    "OFP_ERR_IP_SHORT_PACKET",
                                    "OFP_ERR_IP_INVALID_HEADER",
                                    "OFP_ERR_IP_INVALID_CHECKSUM",
                                    "OFP_ERR_IP_BAD_FRAGMENT",
                                    "OFP_ERR_TCP_SHORT_PACKET",
                                    "OFP_ERR_TCP_INVALID_HEADER",
                                    "OFP_ERR_TCP_INVALID_CHECKSUM",
                                    "OFP_ERR_UDP_SHORT_PACKET",
                                    "OFP_ERR_UDP_INVALID_CHECKSUM",
                                    "OFP_ERR_TCP_SYN_AUTH_NOT_WHITELISTED",
                                    "OFP_ERR_DNS_AMP_RATE_LIMITED",
                                    "OFP_ERR_UDP_RATE_LIMITED",
                                    "OFP_ERR_OUT_OF_MEMORY",
                                    "OFP_ERR_NTP_AMP"
                                    ];

              var startTime;
              var bytesIn = [];
              var bytesOut = [];
              var bytesBadIp = [];
              var bytesParsed = [];
              var ippReceived = [];
              var ippDropped = [];
              var forwardedIcmp = [];
              var forwardedTcp = [];
              var forwardedUdp = [];
              var forwardedOther = [];
              var dropByErrorCode = [15];
              for (var i=0;i<errorCodesName.length;i++) {
                dropByErrorCode[i] = [];
              }
              var totalHostCount = [];
              var totalURLCount = [];
              var loggerDurationMs = [];
              var phishRst = [];
              var frozenCount = [];
              var maxMempoolUsage = [];
              var maxHashUsage = [];
              var cyclePkt = [];

              var phishPacketIn = [];
              var phishPacketParsed = [];
              var phishPacketHttpGet = [];

              var lines = data.split('\n');
              $.each(lines, function(lineNo, line) {
                  var items = line.split(';');
                  if (lineNo == 0) {
                    startTime = parseInt(items[0]) * 1000;
                  }
                  if (items[0]) {
                    ippReceived.push(BigInteger.parse(items[1]).valueOf());
                    bytesIn.push(BigInteger.parse(items[2]).multiply(8).valueOf());
                    bytesOut.push(BigInteger.parse(items[4]).multiply(8).valueOf());
                    ippDropped.push(-BigInteger.parse(items[5]).valueOf());
                    forwardedIcmp.push(BigInteger.parse(items[9]).valueOf());
                    forwardedTcp.push(BigInteger.parse(items[10]).valueOf());
                    forwardedUdp.push(BigInteger.parse(items[11]).valueOf());
                    forwardedOther.push(BigInteger.parse(items[12]).valueOf());

                    phishRst.push(BigInteger.parse(items[15]).valueOf());
                    loggerDurationMs.push(BigInteger.parse(items[16]).valueOf());

                    for (var i = 0; i < errorCodesName.length; i++) {
                      dropByErrorCode[i].push(-BigInteger.parse(items[i+17]).valueOf());
                    }

                    bytesBadIp.push(BigInteger.parse(items[88]).multiply(8).valueOf());
                    bytesParsed.push(BigInteger.parse(items[89]).multiply(8).valueOf());
                    frozenCount.push(BigInteger.parse(items[90]).valueOf());
                    maxMempoolUsage.push(BigInteger.parse(items[91]).valueOf());
                    totalHostCount.push(BigInteger.parse(items[92]).valueOf());
                    totalURLCount.push(BigInteger.parse(items[93]).valueOf());

                    phishPacketIn.push(BigInteger.parse(items[94]).valueOf());
                    phishPacketParsed.push(BigInteger.parse(items[95]).valueOf());
                    phishPacketHttpGet.push(BigInteger.parse(items[96]).valueOf());
                    maxHashUsage.push(BigInteger.parse(items[97]).valueOf());
                    cyclePkt.push(BigInteger.parse(items[98]).valueOf());
                  }
              });

              var options = {
                      chart: {
                          renderTo: 'chartTrafficIn',
                          zoomType: 'x'
                      },
                      title: {
                          text: 'Traffic In/Out'
                      },
                      xAxis: {
                          type: 'datetime',
                          maxZoom:  60000, // 1min
                          lineWidth: 2
                      },
                      yAxis: {
                          title: {
                              text: 'bits/s'
                          }
                      },
                      plotOptions: {
                        series: {
                            marker: {
                              enabled: false
                          }
                        }
                      },
                      series: [
                      {
                          name: 'Out',
                          type: 'area',
                          color: '#55cc55',
                          data: bytesOut,
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'In',
                          type: 'area',
                          data: bytesIn,
                          color: '#FF9900',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'BadIpPort',
                          type: 'area',
                          data: bytesBadIp,
                          color: '#FFCCFF',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'Parsed',
                          type: 'area',
                          color: '#6699FF',
                          data: bytesParsed,
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      ]
              };
              new Highcharts.Chart(options);

              var options = {
                      chart: {
                          renderTo: 'chartPhishPackets',
                          zoomType: 'x'
                      },
                      title: {
                          text: 'Phish packets stats'
                      },
                      xAxis: {
                          type: 'datetime',
                          maxZoom:  60000, // 1min
                          lineWidth: 2
                      },
                      yAxis: {
                          title: {
                              text: 'Packets/s'
                          }
                      },
                      plotOptions: {
                        series: {
                            marker: {
                              enabled: false
                          }
                        }
                      },
                      series: [
                      {
                          name: 'Packet In Phish',
                          type: 'area',
                          data: phishPacketIn,
                          color: '#FF9900',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'Packet parsed',
                          type: 'area',
                          data: phishPacketParsed,
                          color: '#6699FF',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'Packet http get',
                          type: 'area',
                          data: phishPacketHttpGet,
                          color: '#0033FF',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'Phish RST',
                          type: 'area',
                          data: phishRst,
                          color: '#55cc55',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      ]
              };
              new Highcharts.Chart(options);

              var options = {
                      chart: {
                          renderTo: 'tileraHealth',
                          zoomType: 'x'
                      },
                      title: {
                          text: 'Tilera Health'
                      },
                      xAxis: {
                          type: 'datetime',
                          maxZoom:  60000, // 1min
                          lineWidth: 2
                      },
                      yAxis: {
                          title: {
                              text: 'Total'
                          }
                      },
                      plotOptions: {
                        series: {
                            marker: {
                              enabled: false
                          }
                        }
                      },
                      series: [
                      {
                          name: 'max mempool usage',
                          type: 'area',
                          data: maxMempoolUsage,
                          color: '#993399',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'max hash usage',
                          type: 'area',
                          data: maxHashUsage,
                          color: '#3399FF',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'worker frozen',
                          type: 'area',
                          data: frozenCount,
                          color: '#FF0000',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      ]
              };
              new Highcharts.Chart(options);

              var options = {
                      chart: {
                          renderTo: 'chartPerf',
                          zoomType: 'x'
                      },
                      title: {
                          text: 'Perf'
                      },
                      xAxis: {
                          type: 'datetime',
                          maxZoom:  60000, // 1min
                          lineWidth: 2
                      },
                      yAxis: {
                          title: {
                              text: 'Total'
                          }
                      },
                      plotOptions: {
                        series: {
                            marker: {
                              enabled: false
                          }
                        }
                      },
                      series: [
                      {
                          name: 'cyclePkt',
                          type: 'area',
                          data: cyclePkt,
                          color: '#3399FF',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'logger time',
                          type: 'area',
                          data: loggerDurationMs,
                          color: '#55cc55',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      ]
              };
              new Highcharts.Chart(options);

              var options = {
                      chart: {
                          renderTo: 'chartPhishAPI',
                          zoomType: 'x'
                      },
                      title: {
                          text: 'Phish API stats'
                      },
                      xAxis: {
                          type: 'datetime',
                          maxZoom:  60000, // 1min
                          lineWidth: 2
                      },
                      yAxis: {
                          title: {
                              text: 'Total'
                          }
                      },
                      plotOptions: {
                        series: {
                            marker: {
                              enabled: false
                          }
                        }
                      },
                      series: [
                      {
                          name: 'Total URL count',
                          type: 'area',
                          data: totalURLCount,
                          color: '#55cc55',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      {
                          name: 'Total Host count',
                          type: 'area',
                          data: totalHostCount,
                          color: '#bb4455',
                          pointStart: startTime,
                          pointInterval: interval
                      },
                      ]
              };
              new Highcharts.Chart(options);

              var options = {
                      chart: {
                          renderTo: 'chartIpp',
                          zoomType: 'x'
                      },
                      title: {
                          text: 'Ingress Packet Processor'
                      },
                      xAxis: {
                          type: 'datetime',
                          maxZoom:  60000, // 1min
                          lineWidth: 2
                      },
                      yAxis: {
                          title: {
                              text: 'Packets/sec'
                          }
                      },
                      plotOptions: {
                        series: {
                            lineWidth: 1,
                            marker: {
                              enabled: false
                          }
                        }
                      },
                      series: [{
                          name: 'Received',
                          type: 'area',
                          data: ippReceived,
                          pointStart: startTime,
                          pointInterval: interval
                      },{
                          name: 'Dropped',
                          data: ippDropped,
                          pointStart: startTime,
                          pointInterval: interval
                      }]
              };
              new Highcharts.Chart(options);



              var series = [];
              series.push({
                            name: "Forwarded - ICMP",
                            data: forwardedIcmp,
                            pointStart: startTime,
                            pointInterval: interval,
                            color: '#00FF00'
                          });
              series.push({
                            name: "Forwarded - TCP",
                            data: forwardedTcp,
                            pointStart: startTime,
                            pointInterval: interval,
                            color: '#00CC00'
                          });
              series.push({
                            name: "Forwarded - UDP",
                            data: forwardedUdp,
                            pointStart: startTime,
                            pointInterval: interval,
                            color: '#009900'
                          });
              series.push({
                            name: "Forwarded - Other",
                            data: forwardedOther,
                            pointStart: startTime,
                            pointInterval: interval,
                            color: '#006600'
                          });
              for (var i = 0; i < errorCodesName.length; i++) {
                var serie = {
                              name: errorCodesName[i],
                              data: dropByErrorCode[i],
                              pointStart: startTime,
                              pointInterval: interval
                          };
                series.push(serie);
              }
              options = {
                      chart: {
                          renderTo: 'chartPackets',
                          zoomType: 'x',
                          type: 'area'
                      },
                      title: {
                          text: 'Packet actions'
                      },
                      xAxis: {
                          type: 'datetime',
                          maxZoom:  60000, // 1min
                          lineWidth: 2
                      },
                      yAxis: {
                          title: {
                              text: 'Packets/sec'
                          }
                      },
                      plotOptions: {
                              area: {
                                    stacking: 'normal'
                      },
                      series: {
                          lineWidth: 1,
                          marker: {
                            enabled: false
                        }
                      }
                      },
                      series: series
              };
              new Highcharts.Chart(options);

          });

          Highcharts.setOptions({                                            // This is for all plots, change Date axis to local timezone
                global : {
                    useUTC : false
                }
            });
}
