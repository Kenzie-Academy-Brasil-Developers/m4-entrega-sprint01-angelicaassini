import express, { response } from "express";
import users from "./database";
import { v4 as uuidv4 } from "uuid";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();
app.use(express.json());

const port = 3000;

//MIDDLEWARES - são funções que ficam entre o cliente e o controller e podem fazer uma lógica ou verificação que estava repetitiva nos services
const ensureAuthMiddleware = (request, response, next) => {
  let authorization = request.headers.authorization;

  if (!authorization) {
    return response.status(401).json({
      message: "Missing authorization headers",
    });
  }

  authorization = authorization.split(" ")[1];

  return jwt.verify(authorization, process.env.SECRET_KEY, (error, decoded) => {
    if (error) {
      return response.status(401).json({
        message: "Invalid token",
      });
    }

    request.user = {
      id: decoded.sub,
      age: decoded.age,
    };

    return next(request.user);
  });
};

const ensureUserExistsMiddleware = (request, response, next) => {
  const userIndex = users((el) => el.uuid === request.params.id);

  if (userIndex === -1) {
    return response.status(404).json({
      message: "Wrong email/password",
    });
  }

  request.user = {
    userIndex: userIndex,
  };

  return next();
};

const ensureIsAdminMiddleware = (request, response, next) => {
  const user = users.find((el) => el.uuid === request.user.id);
  // console.log("User: ", user);
  // console.log("Request: ", request.user);
  if (user.isAdmin === false) {
    return response.status(403).json({
      message: "missing admin permissions",
    });
  }
  return next(request.user);
};

//SERVICES - lógica e manipulação dos dados
const createUserService = async (userData) => {
  const sameEmail = users.find((el) => el.email === userData.email);

  if (sameEmail) {
    return response.status(409).json({
      message: "Email already registered",
    });
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
    return response.status(401).json({
      message: "Wrong email/password",
    });
  }

  const passwordMatch = await compare(password, user.password);
  if (!passwordMatch) {
    return response(401).json({
      message: "Wrong email/password",
    });
  }

  const token = jwt.sign(
    {
      age: user.age,
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
  const user = {
    ...users[index],
    // decode token
  };
  return [200, user];
};

const updateUserService = (id) => {
  const user = users.find((el) => el.uuid === id);

  const userIndex = users.findIndex((el) => el.uuid === id);

  if (user || users[userIndex].isAdmin) {
    const updatedUser = {
      ...user,
      updatedOn: new Date(),
    };
    return [200, updatedUser];
  }
  return response.status(403).json({
    message: "missing admin permissions",
  });
};

const deleteUserService = (id) => {
  const user = users.find((el) => el.uuid === id);

  const userIndex = users.findIndex((el) => el.uuid === id);

  if (user || users[userIndex].isAdmin) {
    users.splice(userIndex, 1);
    return [200, {}];
  }
  return response.status(403).json({
    message: "missing admin permissions",
  });
};

//CONTROLLERS - recebem os dados da requisição do cliente, e retornam uma resposta p/ o cliente
const createUserController = async (request, response) => {
  const [status, data] = await createUserService(request.body);
  return response.status(status).json(data);
};

const loginUserController = async (request, response) => {
  const [status, data] = await loginUserService(request.body);
  return response.status(status).json(data);
};

const listUsersController = (request, response) => {
  const [status, data] = listUsersService(request);
  return response.status(status).json(data);
};

const listUserProfileController = (request, response) => {
  const [status, data] = listUserProfileService(userIndex);
  return response.status(status).json(data);
};

const updateUserController = (request, response) => {
  const id = request.params.id;
  const [status, data] = updateUserService(id);
  return response.status(status).json(data);
};

const deleteUserController = (request, response) => {
  const id = request.params.id;
  const [status, data] = deleteUserService(id);
  return response.status(status).json(data);
};

//ROTAS
app.post("/users", createUserController);
app.post("/login", loginUserController);
app.get(
  "/users",
  ensureAuthMiddleware,
  ensureIsAdminMiddleware,
  listUsersController
);
app.get(
  "/users/profile",
  ensureAuthMiddleware,
  ensureUserExistsMiddleware,
  listUserProfileController
);
app.patch(
  "/users/:id",
  ensureAuthMiddleware,
  ensureUserExistsMiddleware,
  updateUserController
);
app.delete(
  "/users/:id",
  ensureAuthMiddleware,
  ensureUserExistsMiddleware,
  deleteUserController
);

app.listen(port, () => {
  console.log(`Running server in port ${port}`);
});

export default app;
