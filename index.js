(async () => {
    "use strict"

    // Dependencies
    const client = await require("./modules/mongodb.js")
    const cookieParser = require("cookie-parser")
    const compression = require("compression")
    const sAES256 = require("simple-aes-256")
    const { parse } = require("smol-toml")
    const express = require("express")
    const hashJS = require("hash.js")
    const cryptr = require("cryptr")
    const helmet = require("helmet")
    const path = require("path")
    const fs = require("fs")

    // Variables
    const config = parse(fs.readFileSync("./config.toml", "utf8"))
    const cT = new cryptr(config.security.cookieMasterKey, { encoding: config.security.cookieEncoding, pbkdf2Iterations: config.security.cookiePBKDF2Iterations, saltLength: config.security.cookieSaltLength })
    const web = express()

    const database = client.db(config.database.databaseName)
    const users = database.collection(config.database.usersCollection)

    // Functions
    const SHA512 = (string) => { return hashJS.sha512().update(string).digest("hex") }
    const setCookie = (res, data) => {
        res.cookie("d", data, {
            maxAge: 12 * 60 * 60 * 1000, // 12 hours
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        })
    }

    const dS = async (session) => {
        try {
            const sessionData = JSON.parse(cT.decrypt(session.d))
            return sessionData
        } catch { return false }
    }

    const sAES256E = (password, string) => {return sAES256.encrypt(password, string).toString("hex")}
    const sAES256D = (password, string) => {return sAES256.decrypt(password, Buffer.from(string, "hex")).toString("utf8")}

    const encryptWorkspaceData = (ws, password) => {
        // Variables
        var encrypted = { ...ws }

        // Core
        if (encrypted.name) encrypted.name = sAES256E(password, encrypted.name)
        return encrypted
    }

    const encryptBookmarkData = (b, password) => {
        // Core
        var encrypted = { ...b }
        if (encrypted.name) encrypted.name = sAES256E(password, encrypted.name)
        if (encrypted.description) encrypted.description = sAES256E(password, encrypted.description)
        if (encrypted.links && Array.isArray(encrypted.links)) {
            encrypted.links = encrypted.links.map((col) => {
                var encCol = { ...col }

                if (encCol.name) {
                    try { encCol.name = sAES256E(password, encCol.name) } catch { }
                }

                if (encCol.items && Array.isArray(encCol.items)) {
                    encCol.items = encCol.items.map((item) => {
                        var encItem = { ...item }
                        if (encItem.name) {
                            try { encItem.name = sAES256E(password, encItem.name) } catch { }
                        }

                        if (encItem.url) {
                            try { encItem.url = sAES256E(password, encItem.url) } catch { }
                        }

                        if (encItem.description) {
                            try { encItem.description = sAES256E(password, encItem.description) } catch { }
                        }

                        if (encItem.tags) {
                            var tagsArray = []
                            if (typeof encItem.tags === "string") tagsArray = encItem.tags.split(',').map((t) => t.trim()).filter((t) => t !== '')
                            else if (Array.isArray(encItem.tags)) tagsArray = encItem.tags
                            encItem.tags = tagsArray.map((t) => {
                                try { return sAES256E(password, t) } catch { return t }
                            })
                        }
                        return encItem
                    })
                }
                return encCol
            })
        }
        return encrypted
    }

    const decryptAccountData = (accountData, password) => {
        // Core
        if (!password) return accountData
        if (accountData.workspaces) {
            accountData.workspaces = accountData.workspaces.map((w) => {
                if (w.name) { try { w.name = sAES256D(password, w.name) } catch { } }
                return w
            })
        }
        if (accountData.bookmarks) {
            accountData.bookmarks = accountData.bookmarks.map((b) => {
                if (b.name) { try { b.name = sAES256D(password, b.name) } catch { } }
                if (b.description) { try { b.description = sAES256D(password, b.description) } catch { } }
                if (b.links && typeof b.links === "string") {
                    try {
                        var _parsedLinks = JSON.parse(sAES256D(password, b.links))

                        _parsedLinks.forEach((c) => {
                            if (c.items && Array.isArray(c.items)) {
                                c.items.forEach((i) => {
                                    if (i.tags && typeof i.tags === "string") i.tags = i.tags.split(',').map((t) => t.trim()).filter(Boolean)
                                })
                            }
                        })
                        b.links = _parsedLinks
                    } catch { }
                } else if (b.links && Array.isArray(b.links)) {
                    b.links = b.links.map((col) => {
                        var decryptedCol = { ...col }

                        if (decryptedCol.name) {
                            try { decryptedCol.name = sAES256D(password, decryptedCol.name) } catch { }
                        }

                        if (decryptedCol.items && Array.isArray(decryptedCol.items)) {
                            decryptedCol.items = decryptedCol.items.map((item) => {
                                var decryptedItem = { ...item }

                                if (decryptedItem.name) {
                                    try { decryptedItem.name = sAES256D(password, decryptedItem.name) } catch { }
                                }

                                if (decryptedItem.url) {
                                    try { decryptedItem.url = sAES256D(password, decryptedItem.url) } catch { }
                                }

                                if (decryptedItem.description) {
                                    try { decryptedItem.description = sAES256D(password, decryptedItem.description) } catch { }
                                }

                                if (decryptedItem.tags) {
                                    if (Array.isArray(decryptedItem.tags)) {
                                        decryptedItem.tags = decryptedItem.tags.map((t) => {
                                            try { return sAES256D(password, t) } catch { return t }
                                        })
                                    } else if (typeof decryptedItem.tags === "string") {
                                        decryptedItem.tags = decryptedItem.tags.split(',').map((t) => t.trim()).filter(Boolean)
                                    }
                                }
                                return decryptedItem
                            })
                        }
                        return decryptedCol
                    })
                }
                return b
            })
        }
        return accountData
    }

    // Configurations
    //* Express
    web.use(helmet({ contentSecurityPolicy: false }))
    web.use(compression({ level: 1 }))
    web.use(cookieParser())
    web.use(express.json())
    web.set("views", path.join(__dirname, "views"))
    web.set("view engine", "ejs")
    web.use((req, res, next) => {
        if (req.path.endsWith(".html")) return res.redirect(req.path.replace(/.html$/, ""))
        next()
    })
    web.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }))

    // Main
    web.get("/delete-account", async (req, res) => {
        // Variables
        const userData = await dS(req.cookies)

        // Validations
        if (!userData) return res.redirect("/login")

        // Core
        await users.deleteOne({
            hashedUsername: SHA512(userData.username)
        })
        res.redirect("/login")
    })
    web.get("/logout", (req, res) => res.clearCookie("d").redirect("/"))

    //* API
    web.post("/api/login", async (req, res) => {
        // Variables
        const { username, password } = req.body

        // Validations
        if (!username || !password) return res.send("0")
        const accountData = await users.findOne({
            hashedUsername: SHA512(username),
            password: SHA512(password)
        })
        if (!accountData) return res.send("0")

        // Core
        setCookie(res, cT.encrypt(JSON.stringify({
            username: username,
            password: password
        })))
        res.send("1")
    })

    web.post("/api/register", async (req, res) => {
        // Variables
        const { username, password } = req.body
        if (!config.production.allowRegister) return res.send("2")

        // Validations
        if (!username || !password) return res.send("0")

        // Core
        await users.insertOne({
            hashedUsername: SHA512(username),
            username: sAES256E(password, username),
            password: SHA512(password),
            workspaces: [],
            bookmarks: [], // Contains id (random 67-76 characters uuid), name (string), description (string), links (array), sharedLinks, sharedKey (string), shared (boolen),
            sharedWorkspaces: [],
            sharedBookmarks: [],
            createdDate: Date.now()
        })
        res.send("1")
    })

    web.post("/api/workspace/create", async (req, res) => {
        // Variables
        const { name } = req.body
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !name) return res.send("0")

        // Core
        const workspaceId = SHA512(Date.now().toString() + Math.random().toString())
        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $push: {
                workspaces: {
                    id: workspaceId,
                    name: sAES256E(userData.password, name),
                    icon: null
                }
            }
        })
        res.send("1")
    })

    web.post("/api/workspace/delete/:id", async (req, res) => {
        // Variables
        const workspaceId = req.params.id
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !workspaceId) return res.send("0")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })

        if (accountData) {
            const workspace = accountData.workspaces.find((w) => w.id === workspaceId)
            
            await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
                $pull: { sharedBookmarks: { workspaceId: workspaceId } }
            })

            if (workspace && workspace.shared) {
                const sharedId = workspace.sharedId
                await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
                    $pull: {
                        sharedWorkspaces: { id: sharedId },
                        sharedBookmarks: { workspaceId: sharedId }
                    }
                })
            }
        }

        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $pull: {
                workspaces: {
                    id: workspaceId
                },
                bookmarks: {
                    workspaceId: workspaceId
                }
            }
        })
        
        res.send("1")
    })

    web.post("/api/workspace/update/:id", async (req, res) => {
        // Variables
        const workspaceId = req.params.id
        const { name, icon } = req.body
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !workspaceId) return res.send("0")

        // Core
        const updateDoc = {}
        if (name !== undefined) updateDoc["workspaces.$.name"] = sAES256E(userData.password, name)
        if (icon !== undefined) updateDoc["workspaces.$.icon"] = icon

        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "workspaces.id": workspaceId },
            { $set: updateDoc }
        )
        res.send("1")
    })

    web.post("/api/bookmark/create", async (req, res) => {
        // Variables
        const { name, description, workspaceId } = req.body
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !name || !description || !workspaceId) return res.send("0")

        // Core
        const bookmarkId = SHA512(Date.now().toString() + Math.random().toString())
        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $push: {
                bookmarks: {
                    id: bookmarkId,
                    name: sAES256E(userData.password, name),
                    description: sAES256E(userData.password, description),
                    workspaceId: workspaceId,
                    links: [],
                    globalSettings: {},
                    lastOpened: null
                }
            }
        })
        res.send("1")
    })

    web.post("/api/bookmark/delete/:id", async (req, res) => {
        // Variables
        const bookmarkId = req.params.id
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !bookmarkId) return res.send("0")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (accountData) {
            await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
                $pull: { sharedBookmarks: { originalId: bookmarkId } }
            })
        }

        await users.updateOne({ hashedUsername: SHA512(userData.username) }, {
            $pull: {
                bookmarks: {
                    id: bookmarkId
                }
            }
        })
        res.send("1")
    })

    web.post("/api/workspace/share/:id", async (req, res) => {
        // Variables
        const workspaceId = req.params.id
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !workspaceId) return res.send("0")
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.send("0")

        // Core
        const originalWorkspace = accountData.workspaces.find((w) => w.id === workspaceId)
        if (!originalWorkspace) return res.send("0")
        if (originalWorkspace.shared) return res.send(JSON.stringify({ sharedId: originalWorkspace.sharedId, sharedKey: originalWorkspace.sharedKey }))

        decryptAccountData(accountData, userData.password)
        const decryptedWorkspace = accountData.workspaces.find((w) => w.id === workspaceId)
        const decryptedBookmarks = accountData.bookmarks.filter((b) => b.workspaceId === workspaceId)
        const sharedKey = SHA512(Math.random().toString() + Date.now().toString()).substring(0, 32)
        const sharedWorkspaceId = SHA512(Date.now().toString() + Math.random().toString())

        const individuallySharedIdsToRemove = decryptedBookmarks.filter((b) => b.shared).map((b) => b.sharedId)

        if (individuallySharedIdsToRemove.length > 0) {
            await users.updateOne(
                { hashedUsername: SHA512(userData.username) },
                {
                    $pull: { sharedBookmarks: { id: { $in: individuallySharedIdsToRemove } } },
                    $unset: { "bookmarks.$[elem].shared": "", "bookmarks.$[elem].sharedId": "", "bookmarks.$[elem].sharedKey": "" }
                },
                { arrayFilters: [{ "elem.workspaceId": workspaceId }] }
            )

            decryptedBookmarks.forEach((b) => {
                delete b.shared
                delete b.sharedId
                delete b.sharedKey
            })
        }

        var sharedWorkspace = encryptWorkspaceData(decryptedWorkspace, sharedKey)
        sharedWorkspace.id = sharedWorkspaceId
        sharedWorkspace.originalId = workspaceId

        var sharedBookmarks = decryptedBookmarks.map((b) => {
            var sb = encryptBookmarkData(b, sharedKey)
            sb.id = SHA512(Date.now().toString() + Math.random().toString())
            sb.originalId = b.id
            sb.workspaceId = sharedWorkspaceId
            return sb
        })

        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "workspaces.id": workspaceId },
            {
                $set: { "workspaces.$.shared": true, "workspaces.$.sharedId": sharedWorkspaceId, "workspaces.$.sharedKey": sharedKey },
                $push: { sharedWorkspaces: sharedWorkspace, sharedBookmarks: { $each: sharedBookmarks } }
            }
        )
        res.send(JSON.stringify({ sharedId: sharedWorkspaceId, sharedKey: sharedKey }))
    })

    web.post("/api/workspace/unshare/:id", async (req, res) => {
        // Variables
        const workspaceId = req.params.id
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !workspaceId) return res.send("0")
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.send("0")
        const originalWorkspace = accountData.workspaces.find((w) => w.id === workspaceId)
        if (!originalWorkspace || !originalWorkspace.shared) return res.send("1")

        // Core
        const sharedWorkspaceId = originalWorkspace.sharedId
        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "workspaces.id": workspaceId },
            {
                $unset: { "workspaces.$.shared": "", "workspaces.$.sharedId": "", "workspaces.$.sharedKey": "" },
                $pull: { sharedWorkspaces: { id: sharedWorkspaceId }, sharedBookmarks: { workspaceId: sharedWorkspaceId } }
            }
        )
        res.send("1")
    })

    web.post("/api/bookmark/share/:id", async (req, res) => {
        // Variables
        const bookmarkId = req.params.id
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !bookmarkId) return res.send("0")
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.send("0")
        const originalBookmark = accountData.bookmarks.find((b) => b.id === bookmarkId)
        if (!originalBookmark) return res.send("0")
        const parentWorkspace = accountData.workspaces.find((w) => w.id === originalBookmark.workspaceId)
        if (parentWorkspace && parentWorkspace.shared) return res.send("0")
        if (originalBookmark.shared) return res.send(JSON.stringify({ sharedId: originalBookmark.sharedId, sharedKey: originalBookmark.sharedKey }))

        // Core
        decryptAccountData(accountData, userData.password)
        const decryptedBookmark = accountData.bookmarks.find((b) => b.id === bookmarkId)
        const sharedKey = SHA512(Math.random().toString() + Date.now().toString()).substring(0, 32)
        const sharedBookmarkId = SHA512(Date.now().toString() + Math.random().toString())

        var sharedBookmark = encryptBookmarkData(decryptedBookmark, sharedKey)
        sharedBookmark.id = sharedBookmarkId
        sharedBookmark.originalId = bookmarkId

        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "bookmarks.id": bookmarkId },
            {
                $set: { "bookmarks.$.shared": true, "bookmarks.$.sharedId": sharedBookmarkId, "bookmarks.$.sharedKey": sharedKey },
                $push: { sharedBookmarks: sharedBookmark }
            }
        )
        res.send(JSON.stringify({ sharedId: sharedBookmarkId, sharedKey: sharedKey }))
    })

    web.post("/api/bookmark/unshare/:id", async (req, res) => {
        // Variables
        const bookmarkId = req.params.id
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !bookmarkId) return res.send("0")
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.send("0")
        const originalBookmark = accountData.bookmarks.find((b) => b.id === bookmarkId)
        if (!originalBookmark || !originalBookmark.shared) return res.send("1")
        const parentWorkspace = accountData.workspaces.find((w) => w.id === originalBookmark.workspaceId)
        if (parentWorkspace && parentWorkspace.shared) return res.send("0")

        // Core
        const sharedBookmarkId = originalBookmark.sharedId
        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "bookmarks.id": bookmarkId },
            {
                $unset: { "bookmarks.$.shared": "", "bookmarks.$.sharedId": "", "bookmarks.$.sharedKey": "" },
                $pull: { sharedBookmarks: { id: sharedBookmarkId } }
            }
        )
        res.send("1")
    })

    //* EJS
    web.get("/home", async (req, res) => {
        // Variables
        const userData = await dS(req.cookies)

        // Validations
        if (!userData) return res.redirect("/login")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.redirect("/login")
        decryptAccountData(accountData, userData.password)
        userData.workspaces = accountData.workspaces

        var allBookmarks = accountData.bookmarks || []
        userData.bookmarks = allBookmarks.sort((a, b) => (b.lastOpened || 0) - (a.lastOpened || 0)).slice(0, 10)
        res.render("home", userData)
    })

    web.get("/workspace/:workspaceID", async (req, res) => {
        // Variables
        const workspaceId = req.params.workspaceID
        const shareKey = req.query.key

        if (shareKey) {
            const accountData = await users.findOne({ 'sharedWorkspaces.id': workspaceId })
            if (!accountData) return res.redirect("/home")

            const currentWorkspace = accountData.sharedWorkspaces.find((w) => w.id === workspaceId)
            if (!currentWorkspace) return res.redirect("/home")

            try {
                if (currentWorkspace.name) currentWorkspace.name = sAES256D(shareKey, currentWorkspace.name)
            } catch { return res.redirect("/home") }

            var combinedAccountData = { workspaces: [currentWorkspace], bookmarks: accountData.sharedBookmarks.filter((b) => b.workspaceId === workspaceId) }
            decryptAccountData(combinedAccountData, shareKey)

            return res.render("workspace", {
                username: "Guest",
                workspaces: combinedAccountData.workspaces,
                bookmarks: combinedAccountData.bookmarks,
                currentWorkspace: combinedAccountData.workspaces[0],
                isShared: true,
                shareKey: shareKey
            })
        }

        const userData = await dS(req.cookies)

        // Validations
        if (!userData) return res.redirect("/login")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.redirect("/login")
        decryptAccountData(accountData, userData.password)

        const currentWorkspace = accountData.workspaces.find((w) => w.id === workspaceId)
        if (!currentWorkspace) return res.redirect("/home")

        userData.workspaces = accountData.workspaces
        userData.bookmarks = accountData.bookmarks.filter((b) => b.workspaceId === workspaceId)
        userData.currentWorkspace = currentWorkspace
        res.render("workspace", userData)
    })

    web.get("/bookmark/:bookmarkID", async (req, res) => {
        // Variables
        const bookmarkId = req.params.bookmarkID
        const shareKey = req.query.key

        if (shareKey) {
            const accountData = await users.findOne({ 'sharedBookmarks.id': bookmarkId })
            if (!accountData) return res.redirect("/home")

            const currentBookmark = accountData.sharedBookmarks.find((b) => b.id === bookmarkId)
            if (!currentBookmark) return res.redirect("/home")

            const parentWorkspace = accountData.sharedWorkspaces.find((w) => w.id === currentBookmark.workspaceId)

            var combinedAccountData = { workspaces: parentWorkspace ? [parentWorkspace] : [], bookmarks: [currentBookmark] }
            decryptAccountData(combinedAccountData, shareKey)

            return res.render("links", {
                username: "Guest",
                workspaces: combinedAccountData.workspaces,
                bookmarks: combinedAccountData.bookmarks,
                currentBookmark: combinedAccountData.bookmarks[0],
                currentWorkspace: combinedAccountData.workspaces[0] || { name: 'Shared Workspace' },
                isShared: true,
                shareKey: shareKey
            })
        }

        const userData = await dS(req.cookies)

        // Validations
        if (!userData) return res.redirect("/login")

        const timestamp = Date.now()
        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "bookmarks.id": bookmarkId },
            { $set: { "bookmarks.$.lastOpened": timestamp } }
        )

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.redirect("/login")
        decryptAccountData(accountData, userData.password)

        const currentBookmark = accountData.bookmarks.find((b) => b.id === bookmarkId)
        if (!currentBookmark) return res.redirect("/home")

        userData.workspaces = accountData.workspaces
        userData.currentBookmark = currentBookmark
        userData.currentWorkspace = accountData.workspaces.find((w) => w.id === currentBookmark.workspaceId)

        res.render("links", userData)
    })

    web.get("/bookmark/:bookmarkID/search-engine", async (req, res) => {
        // Variables
        const bookmarkId = req.params.bookmarkID
        const shareKey = req.query.key

        if (shareKey) {
            const accountData = await users.findOne({ 'sharedBookmarks.id': bookmarkId })
            if (!accountData) return res.redirect("/home")

            const currentBookmark = accountData.sharedBookmarks.find((b) => b.id === bookmarkId)
            if (!currentBookmark) return res.redirect("/home")

            const parentWorkspace = accountData.sharedWorkspaces.find((w) => w.id === currentBookmark.workspaceId)

            var combinedAccountData = { workspaces: parentWorkspace ? [parentWorkspace] : [], bookmarks: [currentBookmark] }
            decryptAccountData(combinedAccountData, shareKey)

            return res.render("search-engine", {
                username: "Guest",
                workspaces: combinedAccountData.workspaces,
                bookmarks: combinedAccountData.bookmarks,
                currentBookmark: combinedAccountData.bookmarks[0],
                currentWorkspace: combinedAccountData.workspaces[0] || { name: 'Shared Workspace' },
                isShared: true,
                shareKey: shareKey
            })
        }

        const userData = await dS(req.cookies)

        // Validations
        if (!userData) return res.redirect("/login")

        const timestamp = Date.now()
        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "bookmarks.id": bookmarkId },
            { $set: { "bookmarks.$.lastOpened": timestamp } }
        )

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.redirect("/login")
        decryptAccountData(accountData, userData.password)

        const currentBookmark = accountData.bookmarks.find((b) => b.id === bookmarkId)
        if (!currentBookmark) return res.redirect("/home")

        userData.workspaces = accountData.workspaces
        userData.currentBookmark = currentBookmark
        userData.currentWorkspace = accountData.workspaces.find((w) => w.id === currentBookmark.workspaceId)

        res.render("search-engine", userData)
    })

    web.get("/settings", async (req, res) => {
        // Variables
        const userData = await dS(req.cookies)

        // Validations
        if (!userData) return res.redirect("/login")

        // Core
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.redirect("/login")

        decryptAccountData(accountData, userData.password)
        userData.createdDate = accountData.createdDate
        userData.workspaces = accountData.workspaces
        res.render("settings", userData)
    })

    web.get("/api/fetch-desc", async (req, res) => {
        try {
            // Variables
            const targetUrl = req.query.url

            // Validations
            if (!targetUrl) return res.send("")

            // Core
            const response = await fetch(targetUrl, {
                headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
                signal: AbortSignal.timeout(5000)
            })

            if (!response.ok) return res.send("")
            const text = await response.text()

            const match = text.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)['"]/i) ||
            text.match(/<meta[^>]*content=["']([^"']*)['"'][^>]*name=["']description["']/i) ||
            text.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']*)['"]/i) ||
            text.match(/<meta[^>]*content=["']([^"']*)['"'][^>]*property=["']og:description["']/i)

            if (match && match[1]) {
                const desc = match[1].replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&')
                return res.send(desc)
            }
            res.send("")
        } catch {
            res.send("")
        }
    })

    web.get("/api/favicon", async (req, res) => {
        try {
            // Variables
            const domain = req.query.domain

            // Validations
            if (!domain) return res.status(400).send("")

            // Core
            const fetchFavicon = async (url) => {
                const response = await fetch(url, {
                    headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
                    signal: AbortSignal.timeout(5000)
                })

                if (!response.ok) return false

                return {
                    buffer: await response.arrayBuffer(),
                    contentType: response.headers.get("content-type") || "image/x-icon"
                }
            }

            var data
            try {
                data = await fetchFavicon(`https://icons.duckduckgo.com/ip3/${domain}.ico`)
            } catch {
                try {
                    data = await fetchFavicon(`https://www.google.com/s2/favicons?sz=32&domain=${domain}`)
                } catch {
                    return res.send("")
                }
            }
            
            res.setHeader("Content-Type", data.contentType)
            res.setHeader("Cache-Control", "public, max-age=604800")
            res.send(Buffer.from(data.buffer))
        } catch {
            res.send("")
        }
    })

    web.post("/api/bookmark/update/:id", async (req, res) => {
        // Variables
        const bookmarkId = req.params.id
        const { links, globalSettings } = req.body
        const userData = await dS(req.cookies)

        // Validations
        if (!userData || !bookmarkId) return res.send("0")

        // Core
        var processedLinks = links
        if (typeof processedLinks === "string") {
            try { processedLinks = JSON.parse(processedLinks) } catch { }
        }

        if (Array.isArray(processedLinks)) {
            processedLinks = processedLinks.map((col) => {
                var encCol = { ...col }

                if (encCol.name) {
                    try { encCol.name = sAES256E(userData.password, encCol.name) } catch { }
                }
                if (encCol.items && Array.isArray(encCol.items)) {
                    encCol.items = encCol.items.map((item) => {
                        var encItem = { ...item }

                        if (encItem.name) {
                            try { encItem.name = sAES256E(userData.password, encItem.name) } catch { }
                        }

                        if (encItem.url) {
                            try { encItem.url = sAES256E(userData.password, encItem.url) } catch { }
                        }

                        if (encItem.description) {
                            try { encItem.description = sAES256E(userData.password, encItem.description) } catch { }
                        }

                        if (encItem.tags) {
                            var tagsArray = []
                            if (typeof encItem.tags === "string") tagsArray = encItem.tags.split(',').map((t) => t.trim()).filter((t) => t !== '')
                            else if (Array.isArray(encItem.tags)) tagsArray = encItem.tags
                            encItem.tags = tagsArray.map((t) => {
                                try { return sAES256E(userData.password, t) } catch { return t }
                            })
                        }
                        return encItem
                    })
                }
                return encCol
            })
        }

        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "bookmarks.id": bookmarkId },
            { $set: { "bookmarks.$.links": processedLinks, "bookmarks.$.globalSettings": globalSettings } }
        )
        res.send("1")
    })

    web.post("/api/link/update/:bookmarkId/:linkId", async (req, res) => {
        // Variables
        const { bookmarkId, linkId } = req.params
        const { name, url, description, tags } = req.body
        const userData = await dS(req.cookies)

        // validations
        if (!userData) return res.status(401).send("0")
        if (!bookmarkId || !linkId) return res.status(400).send("0")
        const accountData = await users.findOne({ hashedUsername: SHA512(userData.username) })
        if (!accountData) return res.status(401).send("0")
        const bookmark = accountData.bookmarks.find((b) => b.id === bookmarkId)
        if (!bookmark) return res.status(403).send("0") // User does not own this bookmark

        // Core
        decryptAccountData(accountData, userData.password)
        const decryptedBookmark = accountData.bookmarks.find((b) => b.id === bookmarkId)
        if (!decryptedBookmark || !Array.isArray(decryptedBookmark.links)) return res.status(404).send("0")

        var found = false
        const updatedLinks = decryptedBookmark.links.map((col) => {
            const updatedItems = (col.items || []).map((item) => {
                if (item.id !== linkId) return item
                found = true

                var processedTags = tags
                if (typeof processedTags === "string") processedTags = processedTags.split(',').map((t) => t.trim()).filter(Boolean)
                if (!Array.isArray(processedTags)) processedTags = []

                return {
                    ...item,
                    name:        name        !== undefined ? name        : item.name,
                    url:         url         !== undefined ? url         : item.url,
                    description: description !== undefined ? description : item.description,
                    tags:        processedTags
                }
            })
            return { ...col, items: updatedItems }
        })

        if (!found) return res.status(404).send("0")
        const reEncryptedLinks = updatedLinks.map((col) => {
            var encCol = { ...col }

            if (encCol.name) { try { encCol.name = sAES256E(userData.password, encCol.name) } catch {} }
            if (encCol.items && Array.isArray(encCol.items)) {
                encCol.items = encCol.items.map((item) => {
                    var encItem = { ...item }

                    if (encItem.name)        { try { encItem.name        = sAES256E(userData.password, encItem.name)        } catch {} }

                    if (encItem.url)         { try { encItem.url         = sAES256E(userData.password, encItem.url)         } catch {} }

                    if (encItem.description) { try { encItem.description = sAES256E(userData.password, encItem.description) } catch {} }

                    if (Array.isArray(encItem.tags)) {
                        encItem.tags = encItem.tags.map((t) => { try { return sAES256E(userData.password, t) } catch { return t } })
                    }
                    
                    return encItem
                })
            }
            return encCol
        })

        await users.updateOne(
            { hashedUsername: SHA512(userData.username), "bookmarks.id": bookmarkId },
            { $set: { "bookmarks.$.links": reEncryptedLinks } }
        )
        res.send("1")
    })

    //* Handlers
    web.use("/{*any}", (req, res) => res.redirect("/"))
    web.listen(config.web.port, () => console.log(`ClippedLinks is litening on port ${config.web.port}`))
})()