export function middleware(deps) {
  return function (req, res, next) {
    let path = req.baseUrl + req.path;
    deps.db.incr('visits', path);
    next();
  };
}
export async function getVisits(path) {
  return await serialize.get('visits', path);
}
