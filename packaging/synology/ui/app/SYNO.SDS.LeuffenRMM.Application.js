// DSM desktop application: opens a draggable window on the DSM desktop (like the
// native apps) embedding the agent's status/log page (served at
// /webman/3rdparty/LeuffenRMM/index.html). Built on DSM's ExtJS app framework.
Ext.define("SYNO.SDS.LeuffenRMM.Application.MainWindow", {
    extend: "SYNO.SDS.AppWindow",

    constructor: function (config) {
        config = config || {};
        Ext.apply(config, {
            width: 920,
            height: 640,
            minWidth: 520,
            minHeight: 360,
            maximizable: true,
            minimizable: true,
            resizable: true,
            layout: "fit",
            items: [{
                xtype: "component",
                autoEl: {
                    tag: "iframe",
                    src: "/webman/3rdparty/LeuffenRMM/index.html",
                    frameborder: "0",
                    style: "width:100%;height:100%;border:0;display:block;background:#0f172a"
                }
            }]
        });
        this.callParent([config]);
    }
});

Ext.define("SYNO.SDS.LeuffenRMM.Application.Instance", {
    extend: "SYNO.SDS.AppInstance",
    appWindowName: "SYNO.SDS.LeuffenRMM.Application.MainWindow"
});
