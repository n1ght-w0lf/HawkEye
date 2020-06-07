var options = {
  rankdir: "LR",
};

var g = new dagreD3.graphlib.Graph()
  .setGraph(options)
  .setDefaultEdgeLabel(function() {
    return {};
  });
var proc_data = {}

function connect(ppid, pid) {
	g.setNode(pid, {
		label: proc_data[pid]['name'],
		labelStyle: "fill: #fff; font-weight: 600",
		style: "fill: #3f3f3f00; stroke-width: 4px;" + (proc_data[pid]['injected'] ? "stroke: red" : "stroke: #5f5f5f"),
		rx: 10, ry: 10,
		padding: 15,
	});
	if(ppid != 0)	// not the parent process
		g.setEdge(ppid, pid, {
			label: proc_data[pid]['injected'] ? "Inject" : "",
			labelStyle: "fill: #f00; font-weight: bold; font-size: 20px",
			style: "stroke: #3e92bd; stroke-width: 3px; fill: none; " + (proc_data[pid]['injected'] ? "stroke-dasharray: 5, 5;" : ""),
			arrowheadStyle: "fill: #286D91",
			curve: d3.curveBasis,
		});

	var children = proc_data[pid]['children'];
	if(children.length == 0)
		return;

	for (var i = 0; i < children.length; i++)
		connect(pid, children[i]);
}

function drawProcessFlow(data) {
	proc_data = data;
	connect(0, proc_data["0"]["children"][0]);

	var render = new dagreD3.render();
	var svg = d3.select('svg'),
	    svgGroup = svg.append('g');

	render(svgGroup, g);

	var xCenterOffset = (svg.attr('width') - g.graph().width) / 2;
	svgGroup.attr('transform', 'translate(' + xCenterOffset + ', 20)');
	svg.attr('height', g.graph().height + 40);

	const elem = document.getElementById('panzoom-element')
	const panzoom = Panzoom(elem, {
	  maxScale: 5,
	  step: 0.18,
	});

	const processzoomInButton = document.getElementById('processzoomInButton');
	const processzoomOutButton = document.getElementById('processzoomOutButton');
	const processresetButton = document.getElementById('processresetButton');
	processzoomInButton.addEventListener('click', panzoom.zoomIn);
	processzoomOutButton.addEventListener('click', panzoom.zoomOut);
	processresetButton.addEventListener('click', panzoom.reset);

	// const parent = elem.parentElement;
	// parent.addEventListener('wheel', panzoom.zoomWithWheel);
	// parent.addEventListener('wheel', function(event) {
	//   if (!event.shiftKey) return
	//   panzoom.zoomWithWheel(event)
	// });
}

function fillFileActivity(data) {
	var created  = document.getElementById("file-created");
	var modified = document.getElementById("file-modified");
	var deleted  = document.getElementById("file-deleted");
	var moved    = document.getElementById("file-moved");
	var copied   = document.getElementById("file-copied");

	created.innerHTML  += (data["created"].length <= 100 ? `(${data["created"].length})` : "(100+)");
	modified.innerHTML += (data["modified"].length <= 100 ? `(${data["modified"].length})` : "(100+)");
	deleted.innerHTML  += (data["deleted"].length <= 100 ? `(${data["deleted"].length})` : "(100+)");
	moved.innerHTML    += (data["moved"].length <= 100 ? `(${data["moved"].length})` : "(100+)");
	copied.innerHTML   += (data["copied"].length <= 100 ? `(${data["copied"].length})` : "(100+)");

	var createdList  = document.getElementById("file-created-list");
	var modifiedList = document.getElementById("file-modified-list");
	var deletedList  = document.getElementById("file-deleted-list");
	var movedList    = document.getElementById("file-moved-list");
	var copiedList   = document.getElementById("file-copied-list");

	data["created"].some(function(filePath, idx) {
		createdList.innerHTML += `<li class="list-group-item">${filePath}</li>`;
		return idx == 100;
	});
	data["modified"].some(function(filePath, idx) {
		modifiedList.innerHTML += `<li class="list-group-item">${filePath}</li>`;
		return idx == 100;
	});
	data["deleted"].some(function(filePath, idx) {
		deletedList.innerHTML += `<li class="list-group-item">${filePath}</li>`;
		return idx == 100;
	});
	data["moved"].some(function(fileFromTo, idx) {
		movedList.innerHTML += `<li class="list-group-item">${fileFromTo['from']}  &nbsp;&nbsp; &rarr; &nbsp;&nbsp; ${fileFromTo['to']}</li>`;
		return idx == 100;
	});
	data["copied"].some(function(fileFromTo, idx) {
		copiedList.innerHTML += `<li class="list-group-item">${fileFromTo['from']} &nbsp;&nbsp; &rarr; &nbsp;&nbsp; ${fileFromTo['to']}</li>`;
		return idx == 100;
	});
}

function fillNetworkActivity(data) {
	document.getElementById("network-urls").innerHTML += `(${data["urls"].length})`;
	document.getElementById("network-dns").innerHTML  += `(${data["dns"].length})`;

	var urlsList = document.getElementById("network-urls-list");
	var dnsList  = document.getElementById("network-dns-list");

	data["urls"].forEach(function(url) {
		urlsList.innerHTML += `<li class="list-group-item">${url}</li>`;
	});
	data["dns"].forEach(function(domain) {
		dnsList.innerHTML += `<li class="list-group-item">${domain}</li>`;
	});
}

function fillRegistryActivity(data) {
	var set     = document.getElementById("registry-set");
	var queried = document.getElementById("registry-queried");
	var deleted = document.getElementById("registry-deleted");

	set.innerHTML     += (data["set"].length <=100 ? `(${data["set"].length})` : "(100+)");
	queried.innerHTML += (data["queried"].length <=100 ? `(${data["queried"].length})` : "(100+)");
	deleted.innerHTML += (data["deleted"].length <=100 ? `(${data["deleted"].length})` : "(100+)");

	var setList     = document.getElementById("registry-set-list");
	var queriedList = document.getElementById("registry-queried-list");
	var deletedList = document.getElementById("registry-deleted-list");

	data["set"].some(function(regval, idx) {
		setList.innerHTML += `<li class="list-group-item">${regval}</li>`;
		return idx == 100;
	});
	data["queried"].some(function(regval, idx) {
		queriedList.innerHTML += `<li class="list-group-item">${regval}</li>`;
		return idx == 100;
	});
	data["deleted"].some(function(regval, idx) {
		deletedList.innerHTML += `<li class="list-group-item">${regval}</li>`;
		return idx == 100;
	});
}

function fillGeneralActivity(data) {
	document.getElementById("general-commands").innerHTML += `(${data["commands"].length})`;
	document.getElementById("general-imports").innerHTML  += `(${data["imports"].length})`;
	document.getElementById("general-mutexes").innerHTML  += `(${data["mutexes"].length})`;

	var commandsList = document.getElementById("general-commands-list");
	var importsList  = document.getElementById("general-imports-list");
	var mutexesList  = document.getElementById("general-mutexes-list");

	data["commands"].forEach(function(command) {
		commandsList.innerHTML += `<li class="list-group-item">${command}</li>`;
	});
	data["imports"].forEach(function(api) {
		importsList.innerHTML += `<li class="list-group-item">${api}</li>`;
	});
	data["mutexes"].forEach(function(mutex) {
		mutexesList.innerHTML += `<li class="list-group-item">${mutex}</li>`;
	});
}

$.getJSON("/output/data.json").then(function(data) {
	drawProcessFlow(data["processes"]);
	fillFileActivity(data["files"]);
	fillNetworkActivity(data["network"]);
	fillRegistryActivity(data["registry"]);
	fillGeneralActivity(data["general"]);
});
