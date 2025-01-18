# Inventory_Management_System
APIs to manage Products and Category and Controller of Signing for Users Using JWT Authentication 

 [ApiController]
 [Route("1.SigningUpController")]
 [Authorize]
 public class SigningUpController(IOptions<JwtOptions> jwt, ILogger<SigningUpController> log, ApplicationDbContext context) : ControllerBase
 {
     public IOptions<JwtOptions> Jwt { get; } = jwt;
     public ILogger<SigningUpController> Log { get; } = log;
     public ApplicationDbContext Context { get; } = context;

     [HttpPost]
     [Route("LogIn")]
     [AllowAnonymous]
     public async Task<ActionResult<string>> AuthenticateUser(AuthenticationRequest request)
     {
         Log.LogWarning("there is something wrong in Login API");
         var ExistingUser = await Context.users.FirstOrDefaultAsync(op => op.UserName == request.UserName);
         if (ExistingUser == null || !BCrypt.Net.BCrypt.Verify(request.Password, ExistingUser.Password))//. due to you in SignUp API you put the Password in Hashing way 
         {
             return BadRequest("This User is Not Exist");
         }
         var tokenHandler = new JwtSecurityTokenHandler();
         var tokenDescriptor = new SecurityTokenDescriptor //. will carrying the data from Users
         {
             Issuer = Jwt.Value.Issuer,
             Audience = Jwt.Value.Audinece,
             SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Jwt.Value.SigningKey)), SecurityAlgorithms.HmacSha256),
             Subject = new ClaimsIdentity(new Claim[]    //. will carrying the info of Users 
             {
                new(ClaimTypes.Name, request.UserName),
                new(ClaimTypes.NameIdentifier, ExistingUser.UserID.ToString() )
             }),
             Expires = DateTime.UtcNow.AddMinutes(15)
         };
         var SecurityToken = tokenHandler.CreateToken(tokenDescriptor);
         var accessToken = tokenHandler.WriteToken(SecurityToken);
         var expirationDate = DateTime.UtcNow.AddDays(30);
         var attribute = new AccessTokenTable
         {
             AccessToken = accessToken,
             ExpirationDate = expirationDate
         };
         await Context.access.AddAsync(attribute);
         if (expirationDate > DateTime.UtcNow) //. this condition will be continue for Date of Expiration Date (30 days)
             return Ok($"AccessToken : `{attribute.AccessToken}`,RefreshToken : `{attribute.RefreshToken}` ");
         else
             return BadRequest("Token Generation failed");
     }

     [HttpPost]
     [Route("SignUp")]
     [AllowAnonymous]
     public async Task<ActionResult<int>> CreateUser(UsersInfo user)
     {
         var ExistingUser = await Context.users.FirstOrDefaultAsync(op => op.UserName == user.UserName);//. that's mean UserName will be Unique
         if (ExistingUser != null)
         {
             return BadRequest("UserName or Password is already Exist");
         }
         user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);//. here will add the password in table In hashing Way
         await Context.Set<UsersInfo>().AddAsync(user);
         await Context.SaveChangesAsync();
         return Ok(user.UserID);
     }
     [HttpGet]
     [Route("GettingProfileUsingPassword")]
     public async Task<ActionResult> GettingProfile(AuthenticationRequest request)
     {
         if (string.IsNullOrWhiteSpace(request.UserName) || string.IsNullOrWhiteSpace(request.Password))
         {
             return BadRequest("UserName or Password is InValid");
         }
         var ExistingUsers = await Context.users.FirstOrDefaultAsync(op => op.UserName == request.UserName);
         if (ExistingUsers != null && BCrypt.Net.BCrypt.Verify(request.Password, ExistingUsers.Password))
         {
             return Ok(ExistingUsers);
         }
         else
         {
             return BadRequest("this Profile is not Exist");
         }
     }

 }

 [ApiController]
 [Route("2.ProductsController")]
 [Authorize]
 public class ProductsController( ILogger<ProductsController> logger, ApplicationDbContext context) : ControllerBase
 {
     public ILogger<ProductsController> Logger { get; } = logger;
     public ApplicationDbContext Context { get; } = context;

     
     [HttpGet]
     [Route("GetProduct/{id}")]
     public async Task<ActionResult<int>> GetByID(int id) //.any API has parameter so has model binding 
     {
         var user = User.Identity.Name;//. getting User Name
         var user_id = ((ClaimsIdentity)User.Identity).FindFirst(ClaimTypes.NameIdentifier); // getting User Id
         logger.LogDebug("Getting Products {ID} #" , id); 
         var ExistingProducts = await context.Set<Products>().FindAsync(id);
         if(ExistingProducts == null)
         {
             logger.LogWarning("Product #{id} is Not Found -- Time {X}", id, DateTime.Now);
             return NotFound($"Product with {id} is not Exist");
         }
         return Ok(ExistingProducts);
     }

     [HttpGet]
     [Route("GetAllProducts")]
     public async Task<ActionResult<IEnumerable<Products>>> GetAll()
     {
         var ExistingProducts = await context.Set<Products>().ToListAsync();
         return Ok(ExistingProducts);
     }

     [HttpPost]
     [AllowAnonymous]
     [Route("AddProduct")]
     public async Task<ActionResult<int>> AddNewProduct( Products products)
     {
         if(!ModelState.IsValid)
         {
             return BadRequest("Bad Request");
         }
         await context.Set<Products>().AddAsync(products);
         await context.SaveChangesAsync();
         return Ok(products.ProductID);
     }

     [HttpDelete]
     [Route("DeleteProduct")]
     public async Task<ActionResult> DeleteProductByID(int id )
     {
         var ExistingProducts = await context.Set<Products>().FindAsync(id);
         if (ExistingProducts == null)
         {
             return NotFound("this product is not Exist");
         }
         context.Set<Products>().Remove(ExistingProducts);
         await context.SaveChangesAsync();
         return Ok($"Product with ID `{id}` Has Been Deleted");
     }

     [HttpPut]
     [Route("UpdateProduct")]
     public async Task<ActionResult> UpdateProduct(int id, Products products)
     {
         var ExistingProducts = await context.Set<Products>().FindAsync(id);
         if (ExistingProducts == null)
         {
             return NotFound("this product is not Exist");
         }
         ExistingProducts.ProductName = products.ProductName;
         ExistingProducts.Price = products.Price;
         ExistingProducts.Quantity = products.Quantity;
         context.Set<Products>().Update(ExistingProducts);
         await context.SaveChangesAsync();
         return Ok(ExistingProducts);
     }
 }

 [ApiController]
 [Route("3. CategoryController")]
 [Authorize]
 public class CategoryController : ControllerBase 
 {
     public CategoryController(ApplicationDbContext dbContext)
     {
         DbContext = dbContext;
     }

     public ApplicationDbContext DbContext { get; }

     [HttpGet]
     [Route("Get/id")]
     public async Task<ActionResult> GetCategory(int id)
     {
         var ExistingCategory = await DbContext.Set<Category>().FindAsync(id);
         if (ExistingCategory == null)
         {
             return NotFound("this product is not Exist");
         }
         return Ok(ExistingCategory);
     }

     [HttpDelete]
     [Route("DeleteCategory")]
     public async Task<ActionResult> DeleteCategory(int id )
     {
         var ExistingCategory = await DbContext.Set<Category>().FindAsync(id);
         if (ExistingCategory == null)
         {
             return NotFound("this product is not Exist");
         }
         DbContext.Set<Category>().Remove(ExistingCategory);
         await DbContext.SaveChangesAsync();
         return Ok($"Category with ID `{id}` Has Been Deleted");
     }

     [HttpPost]
     [Route("AddingProcess")]
     //. this products will be added in Query string of URL 
     public async Task<ActionResult<int>> AddingCategory([FromQuery(Name = "cate2")]Category cat, Category category2)
     {
         if (!ModelState.IsValid)
         {
             return BadRequest("Bad Request");
         }
         await DbContext.Set<Category>().AddAsync(cat);
         await DbContext.SaveChangesAsync();
         return Ok(cat.CategoryID);
     }

     [HttpPut]
     [Route("Update")]
     public async Task<ActionResult> UpdateCategory(int id, Category category )
     {
         var ExistingCategory = await DbContext.Set<Category>().FindAsync(id);
         if (ExistingCategory == null)
         {
             return NotFound("this product is not Exist");
         }
         ExistingCategory.CategoryName = category.CategoryName;
         DbContext.Set<Category>().Update(ExistingCategory);
         await DbContext.SaveChangesAsync();
         return Ok(ExistingCategory);
     }
 }
