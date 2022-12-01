import express from "express";
import users from "./database";
import { v4 as uuidv4 } from "uuid";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();
app.use(express.json());

const port = 3001;

//MIDDLEWARES
const ensureAuthMiddleware = (request, response, next) => {
  let authorization = request.headers.authorization;

  if (!authorization) {
    return response.status(401).json({
      message: "Missing authorization headers",
    });
  }

  const token = authorization.split(" ")[1];

  return jwt.verify(token, process.env.SECRET_KEY, (error, decoded) => {
    if (error) {
      return response.status(401).json({
        message: "Invalid token",
      });
    }

    request.user = {
      id: decoded.sub,
      age: decoded.age,
      isAdm: decoded.isAdm,
    };

    // request.user = decoded;

    return next();
  });
};

const ensureUserExistsMiddleware = (request, response, next) => {
  const userIndex = users.findIndex((el) => el.uuid === request.user.id);

  if (userIndex === -1) {
    return response.status(404).json({
      message: "Wrong email/password",
    });
  }

  request.user = userIndex;

  return next();
};

const ensureIsAdmMiddleware = (request, response, next) => {
  const user = users.find((el) => el.uuid === request.user.id);
  if (user.isAdm === false) {
    return response.status(403).json({
      message: "missing admin permissions",
    });
  }
  return next();
};

//SERVICES
const createUserService = async (userData) => {
  const sameEmail = users.find((el) => el.email === userData.email);

  if (sameEmail) {
    return [409, { message: "Email already registered" }];
  }

  const user = {
    ...userData,
    password: await hash(userData.password, 10),
    createdOn: new Date(),
    updatedOn: new Date(),
    uuid: uuidv4(),
  };

  users.push(user);
  return [201, (({ password, ...others }) => others)(user)];
};

const loginUserService = async ({ email, password }) => {
  const user = users.find((el) => el.email === email);

  if (!user) {
    return [401, { message: "Wrong email/password" }];
  }

  const passwordMatch = await compare(password, user.password);
  if (!passwordMatch) {
    return [401, { message: "Wrong email/password" }];
  }

  const token = jwt.sign(
    {
      age: user.age,
      isAdm: user.isAdm,
    },
    process.env.SECRET_KEY,
    {
      expiresIn: "24h",
      subject: user.uuid,
    }
  );

  return [200, { token }];
};

const listUsersService = () => {
  return [200, users];
};

const listUserProfileService = (index) => {
  const userIndex = {
    ...users[index],
  };

  const { password, ...user } = userIndex;

  return [200, user];
};

const updateUserService = async (userToken, payload, id) => {
  const user = users.find((el) => el.uuid === id);
  const userIndex = users.findIndex((el) => el.uuid === id);

  const payloadKeys = Object.keys(payload);

  if (payloadKeys.includes("isAdm")) {
    return [401, { message: "Can´t update isAdmin" }];
  }

  if (payload.password) {
    payload.password = await hash(payload.password, 10);
  }

  if (userToken.id === id || userToken.isAdm === true) {
    const newUser = {
      ...user,
      ...payload,
      updatedOn: new Date(),
    };

    const { password, ...updatedUser } = newUser;

    return [201, updatedUser];
  }
  return [403, { message: "missing admin permissions" }];
};

const deleteUserService = (id_logado_token, id_params) => {
  const userToBeDeleted_Index = users.findIndex((el) => el.uuid === id_params);

  if (id_params === id_logado_token) {
    if (userToBeDeleted_Index !== -1) {
      users.splice(userToBeDeleted_Index, 1);
      return [204, {}];
    }
  }

  const verifYUserLoggedIsAdmin = users.find(
    (el) => el.uuid === id_logado_token
  );

  if (verifYUserLoggedIsAdmin.isAdm === true) {
    if (userToBeDeleted_Index !== -1) {
      users.splice(userToBeDeleted_Index, 1);
      return [204, {}];
    }
  }
  return [403, { message: "missing admin permissions" }];
};

//CONTROLLERS
const createUserController = async (request, response) => {
  const [status, data] = await createUserService(request.body);
  return response.status(status).json(data);
};

const loginUserController = async (request, response) => {
  const [status, data] = await loginUserService(request.body);
  return response.status(status).json(data);
};

const listUsersController = (request, response) => {
  const [status, data] = listUsersService();
  return response.status(status).json(data);
};

const listUserProfileController = (request, response) => {
  const [status, data] = listUserProfileService(request.user);
  return response.status(status).json(data);
};

const updateUserController = async (request, response) => {
  const id = request.params.id;
  const [status, data] = await updateUserService(
    request.user,
    request.body,
    id
  );
  return response.status(status).json(data);
};

const deleteUserController = (request, response) => {
  const id = request.params.id;
  const [status, data] = deleteUserService(request.user.id, id);
  return response.status(status).json(data);
};

//ROTAS
app.post("/users", createUserController);
app.post("/login", loginUserController);
app.get(
  "/users",
  ensureAuthMiddleware,
  ensureIsAdmMiddleware,
  listUsersController
);
app.get(
  "/users/profile",
  ensureAuthMiddleware,
  ensureUserExistsMiddleware,
  listUserProfileController
);
app.patch("/users/:id", ensureAuthMiddleware, updateUserController);
app.delete("/users/:id", ensureAuthMiddleware, deleteUserController);

app.listen(port, () => {
  console.log(`Running server in port ${port}`);
});

export default app;
