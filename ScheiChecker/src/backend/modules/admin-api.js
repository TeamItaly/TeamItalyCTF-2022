export function adminAPI(route, deps) {
  route.post('/login', async (req, res) => {
    if (!req.body.username || typeof req.body.username !== 'string')
      return invalid(req, res, 'Missing username');
    if (!req.body.password || typeof req.body.password !== 'string')
      return invalid(req, res, 'Missing password');

    if (req.body.username.length > 20) return invalid(req, res, 'Username too long');
    if (req.body.password.length > 20) return invalid(req, res, 'Password too long');

    // Prevent brute force attacks
    req.limitData = {};
    req.limitData.username = req.body.username;
    req.limitData.password = req.body.password;
    req.limitData.banPage = 'tooManyAttempts.html';
    let userIP = req.headers['x-forwarded-for'];
    req.limitData = { ...req.limitData, ...(await deps.db.get('auth', userIP, 60)) };
    if (!req.limitData.attempts)
      req.limitData = {
        attempts: 1,
        firstAttempt: Date.now()
      };
    else req.limitData.attempts++;
    if (req.limitData.attempts > 10)
      return res.status(429).sendFile(`html/${req.limitData.banPage}`, { root: '.' });
    await deps.db.set('auth', userIP, req.limitData, 60);

    if (req.body.username !== 'admin') return invalid(req, res, 'Invalid username');
    let token = deps.jwtAuth.generateJwt(req.body.password);
    if (!token) return invalid(req, res, 'Invalid password');
    res.send({
      token: token
    });
  });

  route.get('/isAdmin', deps.jwtAuth.middleware, (req, res) => {
    res.send({
      isAdmin: true
    });
  });

  route.get('/getCTFFlag', deps.jwtAuth.middleware, (req, res) => {
    res.send(JSON.stringify(deps.flag));
  });

  route.get('/getDebugInfo', deps.jwtAuth.middleware, (req, res) => {
    res.send(
      JSON.stringify(
        `Architecture: ${process.arch}\n` +
          `Platform: ${process.platform}\n` +
          `Node: ${process.version}\n` +
          `Uptime: ${process.uptime()}`
      )
    );
  });

  route.post('/changePw', deps.jwtAuth.middleware, (req, res) => {
    if (!req.body.newPw || typeof req.body.newPw !== 'string')
      return res.send(JSON.stringify('Missing old password'));
    if (!req.body.oldPw || typeof req.body.oldPw !== 'string')
      return res.send(JSON.stringify('Missing new password'));

    if (req.body.newPw === req.body.oldPw)
      return res.send(JSON.stringify('New password must be different from old password'));

    if (req.body.oldPw !== deps.adminPassword)
      return res.send(JSON.stringify('Invalid old password'));

    if (req.body.newPw.length > 50)
      return res.send(JSON.stringify('New password must be shorter than 50 characters'));

    deps.adminPassword = req.body.newPw;
    deps.jwtAuth.setPassword(req.body.newPw);
    res.send(JSON.stringify('Changed'));
  });
}

export function invalid(req, res, error) {
  return res.status(200).send({
    token: null,
    error: error || 'Invalid username or password'
  });
}
